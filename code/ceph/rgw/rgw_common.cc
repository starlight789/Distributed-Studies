// -*- mode:C++; tab-width:8; c-basic-offset:2; indent-tabs-mode:t -*-
// vim: ts=8 sw=2 smarttab

#include <errno.h>
#include <vector>
#include <algorithm>
#include <string>
#include <boost/tokenizer.hpp>

#include "json_spirit/json_spirit.h"
#include "common/ceph_json.h"

#include "auth/Crypto.h"
#include "rgw_crypt_sanitize.h"

#include "rgw_op.h"
#include "rgw_common.h"
#include "rgw_acl.h"
#include "rgw_string.h"
#include "rgw_rados.h"
#include "rgw_http_errors.h"

#include "common/ceph_crypto.h"
#include "common/armor.h"
#include "common/errno.h"
#include "common/Clock.h"
#include "common/Formatter.h"
#include "common/perf_counters.h"
#include "common/convenience.h"
#include "common/strtol.h"
#include "include/str_list.h"
#include "include/random.h"

#include <sstream>

#define dout_context g_ceph_context
#define dout_subsys ceph_subsys_rgw

using rgw::IAM::ARN;
using rgw::IAM::Effect;
using rgw::IAM::op_to_perm;
using rgw::IAM::Policy;

PerfCounters *perfcounter = NULL;

const uint32_t RGWBucketInfo::NUM_SHARDS_BLIND_BUCKET(UINT32_MAX);

rgw_http_errors rgw_http_s3_errors({
    { 0, {200, "" }},
    { STATUS_CREATED, {201, "Created" }},
    { STATUS_ACCEPTED, {202, "Accepted" }},
    { ERR_CALLBACK_FAILED, {203, "CallbackFailed" }},
    { STATUS_NO_CONTENT, {204, "NoContent" }},
    { STATUS_PARTIAL_CONTENT, {206, "" }},
    { ERR_PERMANENT_REDIRECT, {301, "PermanentRedirect" }},
    { ERR_WEBSITE_REDIRECT, {301, "WebsiteRedirect" }},
    { STATUS_REDIRECT, {303, "" }},
    { ERR_NOT_MODIFIED, {304, "NotModified" }},
    { EINVAL, {400, "InvalidArgument" }},
    { ERR_INVALID_REQUEST, {400, "InvalidRequest" }},
    { ERR_INVALID_DIGEST, {400, "InvalidDigest" }},
    { ERR_BAD_DIGEST, {400, "BadDigest" }},
    { ERR_INVALID_LOCATION_CONSTRAINT, {400, "InvalidLocationConstraint" }},
    { ERR_ZONEGROUP_DEFAULT_PLACEMENT_MISCONFIGURATION, {400, "ZonegroupDefaultPlacementMisconfiguration" }},
    { ERR_INVALID_BUCKET_NAME, {400, "InvalidBucketName" }},
    { ERR_INVALID_OBJECT_NAME, {400, "InvalidObjectName" }},
    { ERR_UNRESOLVABLE_EMAIL, {400, "UnresolvableGrantByEmailAddress" }},
    { ERR_INVALID_PART, {400, "InvalidPart" }},
    { ERR_INVALID_PART_ORDER, {400, "InvalidPartOrder" }},
    { ERR_REQUEST_TIMEOUT, {400, "RequestTimeout" }},
    { ERR_TOO_LARGE, {400, "EntityTooLarge" }},
    { ERR_TOO_SMALL, {400, "EntityTooSmall" }},
    { ERR_TOO_MANY_BUCKETS, {400, "TooManyBuckets" }},
    { ERR_MALFORMED_XML, {400, "MalformedXML" }},
    { ERR_MALFORMED_JSON, {400, "MalformedJSON" }},
    { ERR_AMZ_CONTENT_SHA256_MISMATCH, {400, "XAmzContentSHA256Mismatch" }},
    { ERR_MALFORMED_DOC, {400, "MalformedPolicyDocument"}},
    { ERR_INVALID_TAG, {400, "InvalidTag"}},
    { ERR_MALFORMED_ACL_ERROR, {400, "MalformedACLError" }},
    { ERR_INVALID_ENCRYPTION_ALGORITHM, {400, "InvalidEncryptionAlgorithmError" }},
    { ERR_INVALID_RETENTION_PERIOD, {400, "InvalidRetentionPeriod"}},
    { ERR_INVALID_IMAGE, {400, "InvalidImageFormat"}},
    { ERR_MIRROR_SOURCE_INVALID, {400, "FetchObjectFailed"}},
    { ERR_LENGTH_REQUIRED, {411, "MissingContentLength" }},
    { EACCES, {403, "AccessDenied" }},
    { EPERM, {403, "AccessDenied" }},
    { ERR_ONLY_ALLOW_MODIFY, {403, "AccessDenied" }},
    { ERR_SIGNATURE_NO_MATCH, {403, "SignatureDoesNotMatch" }},
    { ERR_INVALID_ACCESS_KEY, {403, "InvalidAccessKeyId" }},
    { ERR_USER_SUSPENDED, {403, "UserSuspended" }},
    { ERR_REQUEST_TIME_SKEWED, {403, "RequestTimeTooSkewed" }},
    { ERR_USER_OBJECT_NUM_QUOTA_EXCEEDED, {403, "QuotaExceeded" }},
    { ERR_USER_CAPACITY_QUOTA_EXCEEDED, {403, "QuotaExceeded" }},
    { ERR_BUCKET_OBJECT_NUM_QUOTA_EXCEEDED, {403, "QuotaExceeded" }},
    { ERR_BUCKET_CAPACITY_QUOTA_EXCEEDED, {403, "QuotaExceeded" }},
    { ERR_MFA_REQUIRED, {403, "AccessDenied" }},
    { ERR_OBJECT_NOT_APPENDABLE, {403, "ObjectUnappendable" }},
    { ERR_MIRROR_SOURCE_DENY, {403, "AccessDeniedBySourceUrl" }},
    { ENOENT, {404, "NoSuchKey" }},
    { ERR_NO_SUCH_BUCKET, {404, "NoSuchBucket" }},
    { ERR_NO_SUCH_WEBSITE_CONFIGURATION, {404, "NoSuchWebsiteConfiguration" }},
    { ERR_NO_BUCKET_NAMESPACE, {404, "NoBucketNamespace" }},
    { ERR_NO_SUCH_UPLOAD, {404, "NoSuchUpload" }},
    { ERR_NOT_FOUND, {404, "Not Found"}},
    { ERR_NO_SUCH_LC, {404, "NoSuchLifecycleConfiguration"}},
    { ERR_NO_SUCH_BUCKET_POLICY, {404, "NoSuchBucketPolicy"}},
    { ERR_NO_SUCH_BUCKET_NOTIFICATION, {404, "NoNotificationConfiguration"}},
    { ERR_NO_SUCH_USER, {404, "NoSuchUser"}},
    { ERR_NO_ROLE_FOUND, {404, "NoSuchEntity"}},
    { ERR_NO_SUCH_OBJECT_LOCK_CONFIGURATION, {404, "ObjectLockConfigurationNotFoundError"}},
    { ERR_NO_SUCH_SUBUSER, {404, "NoSuchSubUser"}},
    { ERR_NO_SUCH_IMAGE_STYLE, {404, "NoSuchStyle"}},
    { ERR_NO_IMAGE_PROTECTION, {404, "NoCopyrightProtectionConfiguration"}},
    { ERR_NO_SUCH_ENCRYPTION, {404, "NoSuchBucketEncryption"}},
    { ERR_NO_SUCH_MIRRORING, {404, "NoSuchMirroring" }},
    { CODE_NO_SUCH_USER_QUOTA, {404, "UserQuotaNotConfigured" }},
    { CODE_NO_SUCH_BUCKET_QUOTA, {404, "BucketQuotaNotConfigured" }},
    { ERR_METHOD_NOT_ALLOWED, {405, "MethodNotAllowed" }},
    { ETIMEDOUT, {408, "RequestTimeout" }},
    { EEXIST, {409, "BucketAlreadyExists" }},
    { ERR_USER_EXIST, {409, "UserAlreadyExists" }},
    { ERR_EMAIL_EXIST, {409, "EmailExists" }},
    { ERR_KEY_EXIST, {409, "KeyExists"}},
    { ERR_TAG_CONFLICT, {409, "OperationAborted"}},
    { ERR_ROLE_EXISTS, {409, "EntityAlreadyExists"}},
    { ERR_DELETE_CONFLICT, {409, "DeleteConflict"}},
    { ERR_RENAME_CONFLICT, {409, "RenameConflict"}},
    { ERR_OFFSET_INCORRECT, {409, "OffsetIncorrect"}},
    { ERR_INVALID_BUCKET_STATE, {409, "InvalidBucketState"}},
    { ERR_INVALID_BUCKET_STATE, {409, "InvalidBucketState"}},
    { ERR_INVALID_SECRET_KEY, {400, "InvalidSecretKey"}},
    { ERR_INVALID_KEY_TYPE, {400, "InvalidKeyType"}},
    { ERR_INVALID_CAP, {400, "InvalidCapability"}},
    { ERR_INVALID_TENANT_NAME, {400, "InvalidTenantName" }},
    { ENOTEMPTY, {409, "BucketNotEmpty" }},
    { ERR_PRECONDITION_FAILED, {412, "PreconditionFailed" }},
    { ERANGE, {416, "InvalidRange" }},
    { ERR_UNPROCESSABLE_ENTITY, {422, "UnprocessableEntity" }},
    { ERR_LOCKED, {423, "Locked" }},
    { ERR_MIRROR_FAILED, {424, "MirrorFailed" }},
    { ERR_INVALID_BODY, {400, "ReadBodyError" }},
    { ERR_INTERNAL_ERROR, {500, "InternalError" }},
    { ERR_NOT_IMPLEMENTED, {501, "NotImplemented" }},
    { ERR_SERVICE_UNAVAILABLE, {503, "ServiceUnavailable"}},
    { ERR_ZERO_IN_URL, {400, "InvalidRequest" }},
    { ERR_INVALID_STORAGE_CLASS, {400, "InvalidStorageClass" }},
    { ERR_QPS_EXCEEDED, {403, "QpsOverlimit" }},
    { ENAMETOOLONG, {400, "NameTooLong" }},
    { ERROR_BUCKET_NAMESPACE_NAME_CONFLICT, {409, "NamespaceNameConflict" }},
    { ERROR_BUCKET_NAMESPACE_DIR_EXIST, {409, "NamespaceDirAlreadyExists" }},
    { ERROR_BUCKET_NAMESPACE_PARENT_NOEXIST, {404, "NamespaceParentNotExists" }},
    { ERROR_BUCKET_NAMESPACE_SET_NOT_ALLOWED, {409, "NamespaceNotAllowed" }},
    { ERROR_BUCKET_VERSION_SET_NOT_ALLOWED, {409, "VersionNotAllowed" }},
    { ERROR_BUCKET_DIR_NOT_EMPTY, {409, "DirNotEmpty" }},
    { ERR_MALFORMED_JSON, {400, "MalformedJSON" }},
    { ERR_NO_SUCH_OBJECT_ACL, {404, "ObjectAclNotExists" }},
    { ERR_INAPPROPRIATE_JSON, {400, "InappropriateJSON" }},
    { ERR_NO_SUCH_CORS, {404, "NoSuchCORSConfiguration" }},
    { ERR_NOTIFICATIONS_FORMAT_ERROR, {400, "InvalidArgument"}},
    { ERR_MAX_MESSAGE_LENGTH_EXCEEDED, {400, "MaxMessageLengthExceeded"}},
    { ERR_INVALID_ENCRY_KMS_MK_ID, {400, "InvalidEncryptionKmsMkid"}},
    { ERR_OBJ_LOCK_LOCKED, {409, "ObjectLockAlreadyLocked"}},
    { ERR_OBJ_LOCK_PROGRESS, {409, "ObjectLockAlreadyInProgress"}},
    { ERR_OBJ_LOCK_EXPIRED, {409, "ObjectLockAlreadyExpired"}},
    { ERR_OBJ_NOT_LOCK, {400, "ObjectLockNotLocked"}},
    { ERR_NOT_ALLOW_SHORTEN_RETEN, {400, "NotAllowShortenRetentionday"}},
    { ERR_OBJ_IMMUTABLE, {409, "ObjectImmutable"}},
    { ERR_NO_SUCH_TRASH_DIR, {404, "NoSuchBucketTrashDirectory"}},
    { ERR_INVAL_TRASH_DIR_NAME, {400, "InvalidTrashDirectoryName"}},
    { ERR_INVAILD_STATIC_WEBSITE_FORMAT, {400, "InvalidStaticWebSiteFormat"}},
    { ERR_SYMLINK_TARGET_NOT_EXIST, {404, "SymlinkTargetNotExist"}},
    { ERR_NOT_SYMLINK_OBJECT, {400, "NotSymlink"}},
    { ERR_FILE_ALREADY_EXISTS, {409, "FileAlreadyExists"}},
    { ERR_INVAILD_TARGET_TYPE, {400, "InvalidTargetType"}},
});

#ifdef WITH_BCEBOS
rgw_http_errors_plus_msg rgw_http_bos_errors({
  { 0, {
      200,
      "success",
      ""
    }
  },
  { STATUS_CREATED, {
      201,
      "Created",
      ""
    }
  },
  { STATUS_ACCEPTED, {
      202,
      "Accepted",
      ""
    }
  },
  { ERR_CALLBACK_FAILED, {
      203,
      "success",
      "Callback failed."
    }
  },
  { STATUS_NO_CONTENT, {
      204,
      "NoContent",
      ""
    }
  },
  { STATUS_PARTIAL_CONTENT, {
      206,
      "",
      ""
    }
  },
  { ERR_PERMANENT_REDIRECT, {
      301,
      "PermanentRedirect",
      ""
    }
  },
  { ERR_WEBSITE_REDIRECT, {
      301,
      "WebsiteRedirect",
      ""
    }
  },
  { STATUS_REDIRECT, {
      303,
      "",
      ""
    }
  },
  { ERR_NOT_MODIFIED, {
      304,
      "NotModified",
      ""
    }
  },
  { EINVAL, {
      400,
      "InvalidArgument",
      "Invalid Argument."
    }
  },
  { ERR_INVALID_REQUEST, {
      400,
      "InvalidRequest",
      "Invalid Request."
    }
  },
  { ERR_INVALID_DIGEST, {
      400,
      "InvalidDigest",
      "Invalid Digest."
    }
  },
  { ERR_BAD_DIGEST, {
      400,
      "BadDigest",
      "The Content-MD5 or x-bce-content-sha256 or x-bce-content-crc32 you specified did not match what we received."
    }
  },
  { ERR_INVALID_LOCATION_CONSTRAINT, {
      400,
      "InvalidLocationConstraint",
      ""
    }
  },
  { ERR_ZONEGROUP_DEFAULT_PLACEMENT_MISCONFIGURATION, {
      400,
      "ZonegroupDefaultPlacementMisconfiguration",
      ""
    }
  },
  { ERR_INVALID_BUCKET_NAME, {
      400,
      "InvalidBucketName",
      "The specified bucket is not valid."
    }
  },
  { ERR_INVALID_OBJECT_NAME, {
      400,
      "InvalidObjectName",
      "Your object key is too long."
    }
  },
  { ERR_UNRESOLVABLE_EMAIL, {
      400,
      "UnresolvableGrantByEmailAddress",
      ""
    }
  },
  { ERR_INVALID_PART, {
      400,
      "InvalidPart",
      "One or more of the specified parts could not be found. The part might not have been uploaded, or the specified entity tag might not have matched the part's entity tag."
    }
  },
  { ERR_INVALID_PART_ORDER, {
      400,
      "InvalidPartOrder",
      "The list of parts was not in ascending order.Parts list must specified in order by part number."
    }
  },
  { ERR_REQUEST_TIMEOUT, {
      400,
      "RequestTimeout",
      "Your socket connection to the server was not read from or written to within the timeout period."
    }
  },
  { ERR_TOO_LARGE, {
      400,
      "EntityTooLarge",
      "Your proposed upload exceeds the maximum allowed object size."
    }
  },
  { ERR_TOO_SMALL, {
      400,
      "EntityTooSmall",
      "Your proposed upload is smaller than the minimum allowed object size."
    }
  },
  { ERR_TOO_MANY_BUCKETS, {
      400,
      "TooManyBuckets",
      "You have attempted to create more buckets than allowed."
    }
  },
  { ERR_MALFORMED_XML, {
      400,
      "MalformedXML",
      "The XML you provided was not well-formed or did not validate against our published schema."
    }
  },
  { ERR_AMZ_CONTENT_SHA256_MISMATCH, {
      400,
      "XAmzContentSHA256Mismatch",
      ""
    }
  },
  { ERR_MALFORMED_DOC, {
      400,
      "MalformedPolicyDocument",
      ""
    }
  },
  { ERR_INVALID_TAG, {
      400,
      "InvalidTag",
      ""
    }
  },
  { ERR_MALFORMED_ACL_ERROR, {
      400,
      "MalformedACLError",
      ""
    }
  },
  { ERR_INVALID_ENCRYPTION_ALGORITHM, {
      400,
      "InvalidEncryptionAlgorithm",
      "The specified encryption algorithm is invalid"
    }
  },
  { ERR_INVALID_RETENTION_PERIOD, {
      400,
      "InvalidRetentionPeriod",
      ""
    }
  },
  { ERR_INVALID_IMAGE, {
      400,
      "InvalidImageFormat",
      "Your image format is invalid."
    }
  },
  { ERR_NOTIFICATIONS_FORMAT_ERROR, {
      400,
      "InvalidArgument",
      ""
    }
  },
  { ERR_INAPPROPRIATE_JSON, {
      400,
      "InappropriateJSON",
      "The format of json object is inappropriate."
    }
  },
  { ERR_MALFORMED_JSON, {
      400,
      "MalformedJSON",
      "The JSON you provided was not well-formed."
    }
  },
  { ERR_INVALID_SECRET_KEY, {
      400,
      "InvalidSecretKey",
      ""
    }
  },
  { ERR_INVALID_KEY_TYPE, {
      400,
      "InvalidKeyType",
      ""
    }
  },
  { ERR_INVALID_CAP, {
      400,
      "InvalidCapability",
      ""
    }
  },
  { ERR_INVALID_TENANT_NAME, {
      400,
      "InvalidTenantName",
      ""
    }
  },
  { ENAMETOOLONG, {
      400,
      "MetadataTooLarge",
      "Your metadata headers exceed the maximum allowed metadata size."
    }
  },
  { ERR_ZERO_IN_URL, {
      400,
      "InvalidRequest",
      ""
    }
  },
  { ERR_INVALID_ENCRY_KMS_MK_ID, {
      400,
      "InvalidEncryptionKmsMkid",
      ""
    }
  },
  { ERR_INVALID_STORAGE_CLASS, {
      400,
      "InvalidArgument", // align to bos, although i think this is very weird
      "The storage class specified is invalid, please check argument and consult the service documentation."
    }
  },
  { ERR_MAX_MESSAGE_LENGTH_EXCEEDED, {
      400,
      "MaxMessageLengthExceeded",
      "Your request was too big."
    }
  },
  { ERR_INVALID_SESSION_TOKEN, {
      400,
      "InvalidSessionToken",
      "The Session Token you provided is not valid. Please double check that you are using the correct Session Token obtained from STS (Security Token Service)"
    }
  },
  { ERR_INVALID_BODY, {
      400,
      "ReadBodyError",
      "Read http body error, please try again"
    }
  },
  { ERR_INVAILD_STATIC_WEBSITE_FORMAT, {
      400,
      "InvalidStaticWebSiteFormat",
      "The format of index file or 404 file are not allowed."
    }
  },
  { EACCES, {
      403,
      "AccessDenied",
      "Access Denied."
    }
  },
  { EPERM, {
      403,
      "AccessDenied",
      "Access Denied."
    }
  },
  { ERR_ONLY_ALLOW_MODIFY, {
      403,
      "OnlyAllowModify",
      "Permission not match, you only have modify permission, so you can not upload a new object"
    }
  },
  { ERR_SIGNATURE_NO_MATCH, {
      403,
      "SignatureDoesNotMatch",
      "The request signature we calculated does not match the signature you provided. Check your Secret Access Key and signing method. Consult the service documentation for details."
    }
  },
  { ERR_INVALID_ACCESS_KEY, {
      403,
      "InvalidAccessKeyId",
      "The BCS Access Key Id you provided does not exist in our records."
    }
  },
  { ERR_USER_SUSPENDED, {
      403,
      "UserSuspended",
      ""
    }
  },
  { ERR_REQUEST_TIME_SKEWED, {
      403,
      "RequestTimeTooSkewed",
      "The difference between the request time and the server's time is too large."
    }
  },
  { ERR_USER_OBJECT_NUM_QUOTA_EXCEEDED, {
      403,
      "ObjectNumExceeded",
      "Your total upload object number exceeds the maxinum in your account"
    }
  },
  { CODE_NO_SUCH_USER_QUOTA, {
      404,
      "UserQuotaNotConfigured",
      "The user quota does not configured"
    }
  },
  { CODE_NO_SUCH_BUCKET_QUOTA, {
      404,
      "BucketQuotaNotConfigured",
      "The bucket quota does not configured"
    }
  },
  { ERR_USER_CAPACITY_QUOTA_EXCEEDED, {
      403,
      "CapacityExceeded",
      "Your total upload bytes exceeds the maximum allowed in your account."
    }
  },
  { ERR_BUCKET_OBJECT_NUM_QUOTA_EXCEEDED, {
      403,
      "BucketObjectNumExceeded",
      "Your total upload object number exceeds the maxinum in your bucket"
    }
  },
  { ERR_BUCKET_CAPACITY_QUOTA_EXCEEDED, {
      403,
      "BucketCapacityExceeded",
      "Your total upload bytes exceeds the maximum allowed in your bucket"
    }
  },
  { ERR_MFA_REQUIRED, {
      403,
      "AccessDenied",
      ""
    }
  },
  { ENOENT, {
      404,
      "NoSuchKey",
      "The specified key does not exist."
    }
  },
  { ERR_NO_SUCH_BUCKET, {
      404,
      "NoSuchBucket",
      "The specified bucket does not exist."
    }
  },
  { ERR_NO_SUCH_WEBSITE_CONFIGURATION, {
      404,
      "NoSuchBucketStaticWebSiteConfig",
      "The static web site configuration does not exist."
    }
  },
  { ERR_NO_BUCKET_NAMESPACE, {
      404,
      "NoBucketNamespace",
      ""
    }
  },
  { ERR_NO_SUCH_ENCRYPTION, {
      404,
      "NoSuchBucketEncryption",
      ""
    }
  },
  { ERR_NO_SUCH_UPLOAD, {
      404,
      "NoSuchUpload",
      "The specified multipart upload does not exist. The upload ID might be invalid, or the multipart upload might have been aborted or completed."
    }
  },
  { ERR_NOT_FOUND, {
      404,
      "Not Found",
      ""
    }
  },
  { ERR_NO_SUCH_LC, {
      404,
      "NoLifecycleConfiguration",
      "The lifecycle configuration does not exist."
    }
  },
  { ERR_NO_SUCH_BUCKET_POLICY, {
      404,
      "NoSuchBucketPolicy",
      ""
    }
  },
  { ERR_NO_SUCH_BUCKET_NOTIFICATION, {
      404,
      "NoNotificationConfiguration",
      "The notification configuration does not exist."
    }
  },
  { ERR_NO_SUCH_USER, {
      404,
      "NoSuchUser",
      ""
    }
  },
  { ERR_NO_ROLE_FOUND, {
      404,
      "NoSuchEntity",
      ""
    }
  },
  { ERR_NO_SUCH_OBJECT_LOCK_CONFIGURATION, {
      404,
      "NoSuchObjectLock",
      "The specified object lock does not exist."
    }
  },
  { ERR_NO_SUCH_SUBUSER, {
      404,
      "NoSuchSubUser",
      ""
    }
  },
  { ERR_NO_IMAGE_PROTECTION, {
      404,
      "NoCopyrightProtectionConfiguration",
      "The copyright protection configuration does not exist."
    }
  },
  { ERR_NO_SUCH_IMAGE_STYLE, {
      404,
      "NoSuchStyle",
      "The specified style does not exist."
    }
  },
  { ERR_NO_SUCH_OBJECT_ACL, {
      404,
      "ObjectAclNotExists",
      "The object acl does not exist."
    }
  },
  
  { ERR_NO_SUCH_CORS, {
      404,
      "NoSuchCORSConfiguration",
      "The CORS configuration does not exist."
    }
  },
  { ERROR_BUCKET_NAMESPACE_PARENT_NOEXIST, {
      404,
      "NamespaceParentNotExists",
      ""
    }
  },
  { ERR_NO_SUCH_TRASH_DIR, {
      404,
      "NoSuchBucketTrashDirectory",
      "The bucket does not activate trash, or trash has been turned off"
    }
  },
  { ERR_INVAL_TRASH_DIR_NAME, {
      400,
      "InvalidTrashDirectoryName",
      "Your trash directory name is not valid."
    }
  },
  { ERR_METHOD_NOT_ALLOWED, {
      405,
      "MethodNotAllowed",
      "The specified method is not allowed against this resource."
    }
  },
  { ETIMEDOUT, {
      408,
      "RequestTimeout",
      "Your socket connection to the server was not read from or written to within the timeout period."
    }
  },
  { EEXIST, {
      409,
      "BucketAlreadyExists",
      "The requested bucket name is not available. The bucket namespace is shared by all users of the system. Please select a different name and try again."
    }
  },
  { ERR_USER_EXIST, {
      409,
      "UserAlreadyExists",
      ""
    }
  },
  { ERR_EMAIL_EXIST, {
      409,
      "EmailExists",
      ""
    }
  },
  { ERR_KEY_EXIST, {
      409,
      "KeyExists",
      ""
    }
  },
  { ERR_TAG_CONFLICT, {
      409,
      "OperationAborted",
      ""
    }
  },
  { ERR_ROLE_EXISTS, {
      409,
      "EntityAlreadyExists",
      ""
    }
  },
  { ERR_DELETE_CONFLICT, {
      409,
      "DeleteConflict",
      ""
    }
  },
  { ERR_OFFSET_INCORRECT, {
      409,
      "OffsetIncorrect",
      "Offset not equal to current object length"
    }
  },
  { ERR_OBJECT_NOT_APPENDABLE, {
      403,
      "ObjectUnappendable",
      "The object can not be append"
    }
  },
  { ERR_INVALID_BUCKET_STATE, {
      409,
      "InvalidBucketState",
      ""
    }
  },
  { ENOTEMPTY, {
      409,
      "BucketNotEmpty",
      "The bucket you tried to delete is not empty."
    }
  },
  { ERROR_BUCKET_NAMESPACE_NAME_CONFLICT, {
      409,
      "NamespaceNameConflict",
      ""
    }
  },
  { ERROR_BUCKET_NAMESPACE_DIR_EXIST, {
      409,
      "NamespaceDirAlreadyExists",
      ""
    }
  },
  
  { ERROR_BUCKET_NAMESPACE_SET_NOT_ALLOWED, {
      409,
      "NamespaceNotAllowed",
      ""
    }
  },
  { ERROR_BUCKET_VERSION_SET_NOT_ALLOWED, {
      409,
      "VersionNotAllowed",
      ""
    }
  },
  { ERROR_BUCKET_DIR_NOT_EMPTY, {
      409,
      "DirNotEmpty",
      ""
    }
  },
  { ERR_LENGTH_REQUIRED, {
      411,
      "MissingContentLength",
      "You must provide the Content-Length HTTP header."
    }
  },
  { ERR_PRECONDITION_FAILED, {
      412,
      "PreconditionFailed",
      "The specified If-Match header doesn't match the header you provided."
    }
  },
  { ERANGE, {
      416,
      "InvalidRange",
      "The requested range cannot be satisfied."
    }
  },
  { ERR_UNPROCESSABLE_ENTITY, {
      422,
      "UnprocessableEntity",
      ""
    }
  },
  { ERR_LOCKED, {
      423,
      "Locked",
      ""
    }
  },
  
  
  { ERR_QPS_EXCEEDED, {
      429,
      "RequestRateLimitExceeded",
      "Your request rate is too high. We have put limits on your bucket."
    }
  },
  
  { ERR_INTERNAL_ERROR, {
      500,
      "InternalError",
      "We encountered an internal error. Please try again."
    }
  },
  { ERR_NOT_IMPLEMENTED, {
      501,
      "NotImplemented",
      "A header you provided implies functionality that is not implemented."
    }
  },
  { ERR_SERVICE_UNAVAILABLE, {
      503,
      "ServiceUnavailable",
      "Please reduce your request rate."
    }
  },
  {
    ERR_OBJ_LOCK_LOCKED, {
      409,
      "ObjectLockAlreadyLocked",
      "The object lock status is locked."
    }
  },
  {
    ERR_OBJ_LOCK_PROGRESS, {
      409,
      "ObjectLockAlreadyInProgress",
      "The bucket lock status is already InProgress"
    }
  },
  {
    ERR_OBJ_LOCK_EXPIRED, {
      409,
      "ObjectLockAlreadyExpired",
      "The object lock status is expired."
    }
  },
  {
    ERR_OBJ_NOT_LOCK, {
      400,
      "ObjectLockNotLocked",
      "The object lock is not locked, can not extend retentionday"
    }
  },
  {
    ERR_NOT_ALLOW_SHORTEN_RETEN, {
      400,
      "NotAllowShortenRetentionday",
      "Could not shorten retentionday"
    }
  },
  {
    ERR_OBJ_IMMUTABLE, {
      409,
      "ObjectImmutable",
      "The object is immutable"
    }
  },
  { ERR_SYMLINK_TARGET_NOT_EXIST, {
      404,
      "SymlinkTargetNotExist",
      "The specified object key is symlink, target object of symlink does not exist."
    }
  },
  { ERR_NOT_SYMLINK_OBJECT, {
      400,
      "NotSymlink",
      "The specified object key is not symlink."
    }
  },
  { ERR_FILE_ALREADY_EXISTS, {
      409,
      "FileAlreadyExists",
      "This file already exists."
    }
  },
  { ERR_INVAILD_TARGET_TYPE, {
      400,
      "InvalidTargetType",
      "The specified object key is symlink, target object of symlink also is symlink."
    }
  },
});
#endif // WITH_BCEBOS

rgw_http_errors rgw_http_swift_errors({
    { EACCES, {403, "AccessDenied" }},
    { EPERM, {401, "AccessDenied" }},
    { ENAMETOOLONG, {400, "Metadata name too long" }},
    { ERR_USER_SUSPENDED, {401, "UserSuspended" }},
    { ERR_INVALID_UTF8, {412, "Invalid UTF8" }},
    { ERR_BAD_URL, {412, "Bad URL" }},
    { ERR_NOT_SLO_MANIFEST, {400, "Not an SLO manifest" }},
    { ERR_QUOTA_EXCEEDED, {413, "QuotaExceeded" }},
    { ENOTEMPTY, {409, "There was a conflict when trying "
                       "to complete your request." }},
    /* FIXME(rzarzynski): we need to find a way to apply Swift's error handling
     * procedures also for ERR_ZERO_IN_URL. This make a problem as the validation
     * is performed very early, even before setting the req_state::proto_flags. */
    { ERR_ZERO_IN_URL, {412, "Invalid UTF8 or contains NULL"}},
});

int rgw_perf_start(CephContext *cct)
{
  PerfCountersBuilder plb(cct, "rgw", l_rgw_first, l_rgw_last);

  // RGW emits comparatively few metrics, so let's be generous
  // and mark them all USEFUL to get transmission to ceph-mgr by default.
  plb.set_prio_default(PerfCountersBuilder::PRIO_USEFUL);

  plb.add_u64_counter(l_rgw_req, "req", "Requests");
  plb.add_u64_counter(l_rgw_failed_req, "failed_req", "Aborted requests");

  plb.add_u64_counter(l_rgw_get, "get", "Gets");
  plb.add_u64_counter(l_rgw_get_b, "get_b", "Size of gets");
  plb.add_time_avg(l_rgw_get_lat, "get_initial_lat", "Get latency");
  plb.add_u64_counter(l_rgw_put, "put", "Puts");
  plb.add_u64_counter(l_rgw_put_b, "put_b", "Size of puts");
  plb.add_time_avg(l_rgw_put_before_put_meta, "rgw_put_before_put_meta", "befor put meta latency");

  plb.add_time_avg(l_rgw_put_prepare_index, "rgw_put_prepare_index", "prepare put index op latency");
  plb.add_time_avg(l_rgw_put_prepare_namespace, "rgw_put_prepare_namespace", "prepare put namespace op latency");
  plb.add_time_avg(l_rgw_put_quick_prepare_namespace_lat, "rgw_put_quick_prepare_namespace_lat", "quick prepare namespace op latency");
  plb.add_time_avg(l_rgw_put_slow_prepare_namespace_lat, "rgw_put_slow_prepare_namespace_lat", "slow prepare namespace op latency");
  plb.add_u64_avg(l_rgw_put_prepare_namespace_cls_op, "rgw_put_prepare_namespace_cls_op", "prepare namespace cls op numbers");
  plb.add_u64_counter(l_rgw_put_prepare_namespace_cancel, "rgw_put_prepare_namespace_cancel", "prepare cancel requests");

  plb.add_time_avg(l_rgw_put_head_meta, "rgw_put_head_meta", "put head and meta latency");
  plb.add_time_avg(l_rgw_put_complete_index, "rgw_put_complete_index", "complete index op latency");
  plb.add_time_avg(l_rgw_put_complete_namespce, "rgw_put_complete_namespce", "complete namespace op latency");
  plb.add_u64_counter(l_rgw_put_complete_namespce_cancel, "rgw_put_complete_namespce_cancel", "complete cancel requests");
  plb.add_time_avg(l_rgw_put_lat, "put_initial_lat", "Put latency");

  plb.add_time_avg(l_rgw_list_cls_list_namespace_lat, "rgw_list_cls_list_lat", "the latency of cls list");
  plb.add_time_avg(l_rgw_list_reuslt_process_namespace_lat, "rgw_list_reuslt_process_lat", "the latency of process cls list result");
  plb.add_time_avg(l_rgw_list_namespace_lat, "rgw_list_lat", "the latency of from start to before send response");

  plb.add_u64(l_rgw_qlen, "qlen", "Queue length");
  plb.add_u64(l_rgw_qactive, "qactive", "Active requests queue");

  plb.add_u64_counter(l_rgw_cache_hit, "cache_hit", "Cache hits");
  plb.add_u64_counter(l_rgw_cache_miss, "cache_miss", "Cache miss");

  plb.add_u64_counter(l_rgw_keystone_token_cache_hit, "keystone_token_cache_hit", "Keystone token cache hits");
  plb.add_u64_counter(l_rgw_keystone_token_cache_miss, "keystone_token_cache_miss", "Keystone token cache miss");

  plb.add_u64_counter(l_rgw_gc_retire, "gc_retire_object", "GC object retires");

  plb.add_u64_counter(l_rgw_lc_expire_current, "lc_expire_current", "Lifecycle current expiration");
  plb.add_u64_counter(l_rgw_lc_expire_noncurrent, "lc_expire_noncurrent", "Lifecycle non-current expiration");
  plb.add_u64_counter(l_rgw_lc_expire_dm, "lc_expire_dm", "Lifecycle delete-marker expiration");
  plb.add_u64_counter(l_rgw_lc_transition_current, "lc_transition_current", "Lifecycle current transition");
  plb.add_u64_counter(l_rgw_lc_transition_noncurrent, "lc_transition_noncurrent", "Lifecycle non-current transition");
  plb.add_u64_counter(l_rgw_lc_abort_mpu, "lc_abort_mpu", "Lifecycle abort multipart upload");

  perfcounter = plb.create_perf_counters();
  cct->get_perfcounters_collection()->add(perfcounter);
  return 0;
}

void rgw_perf_stop(CephContext *cct)
{
  assert(perfcounter);
  cct->get_perfcounters_collection()->remove(perfcounter);
  delete perfcounter;
}

using namespace ceph::crypto;

rgw_err::
rgw_err()
{
  clear();
}

void rgw_err::
clear()
{
  http_ret = 200;
  ret = 0;
  err_code.clear();
}

bool rgw_err::
is_clear() const
{
  return (http_ret == 200);
}

bool rgw_err::
is_err() const
{
  return !(http_ret >= 200 && http_ret <= 399);
}

// The requestURI transferred from the frontend can be abs_path or absoluteURI
// If it is absoluteURI, we should adjust it to abs_path for the following 
// S3 authorization and some other processes depending on the requestURI
// The absoluteURI can start with "http://", "https://", "ws://" or "wss://"
static string get_abs_path(const string& request_uri) {
  const static string ABS_PREFIXS[] = {"http://", "https://", "ws://", "wss://"};
  bool isAbs = false;
  for (int i = 0; i < 4; ++i) {
    if (boost::algorithm::starts_with(request_uri, ABS_PREFIXS[i])) {
      isAbs = true;
      break;
    } 
  }
  if (!isAbs) {  // it is not a valid absolute uri
    return request_uri;
  }
  size_t beg_pos = request_uri.find("://") + 3;
  size_t len = request_uri.size();
  beg_pos = request_uri.find('/', beg_pos);
  if (beg_pos == string::npos) return request_uri;
  return request_uri.substr(beg_pos, len - beg_pos);
}

req_info::req_info(CephContext *cct, const class RGWEnv *env) : env(env) {
  method = env->get("REQUEST_METHOD", "");
  script_uri = env->get("SCRIPT_URI", cct->_conf->rgw_script_uri.c_str());
  request_uri = env->get("REQUEST_URI", cct->_conf->rgw_request_uri.c_str());
  if (request_uri[0] != '/') {
    request_uri = get_abs_path(request_uri);
  }
  auto pos = request_uri.find('?');
  if (pos != string::npos) {
    request_params = request_uri.substr(pos + 1);
    request_uri = request_uri.substr(0, pos);
  } else {
    request_params = env->get("QUERY_STRING", "");
  }
  host = env->get("HTTP_HOST", "");

  // strip off any trailing :port from host (added by CrossFTP and maybe others)
  size_t colon_offset = host.find_last_of(':');
  if (colon_offset != string::npos) {
    bool all_digits = true;
    for (unsigned i = colon_offset + 1; i < host.size(); ++i) {
      if (!isdigit(host[i])) {
	all_digits = false;
	break;
      }
    }
    if (all_digits) {
      host.resize(colon_offset);
    }
  }
}

void req_info::rebuild_from(req_info& src)
{
  method = src.method;
  script_uri = src.script_uri;
  args = src.args;
  if (src.effective_uri.empty()) {
    request_uri = src.request_uri;
  } else {
    request_uri = src.effective_uri;
  }
  effective_uri.clear();
  host = src.host;

  x_meta_map = src.x_meta_map;
  x_meta_map.erase("x-amz-date");
#ifdef WITH_BCEBOS
  x_exclude_bce_meta_map = src.x_exclude_bce_meta_map;
  x_exclude_bce_meta_map.erase("x-amz-date");
#endif
}


req_state::req_state(CephContext* _cct, RGWEnv* e, RGWUserInfo* u)
  : cct(_cct), user(u),
    info(_cct, e)
{
  enable_ops_log = e->get_enable_ops_log();
  enable_usage_log = e->get_enable_usage_log();
  defer_to_bucket_acls = e->get_defer_to_bucket_acls();

  time = Clock::now();
}

req_state::~req_state() {
  delete formatter;
}

bool search_err(rgw_http_errors& errs, int err_no, int& http_ret, string& code)
{
  auto r = errs.find(err_no);
  if (r != errs.end()) {
    http_ret = r->second.first;
    code = r->second.second;
    return true;
  }
  return false;
}

bool search_err(rgw_http_errors_plus_msg& errs, int err_no, int& http_ret, string& code, string& msg)
{
  auto r = errs.find(err_no);
  if (r != errs.end()) {
    http_ret = std::get<0>(r->second);
    code = std::get<1>(r->second);
    if (msg.empty()) {
      msg = std::get<2>(r->second);
    }
    return true;
  }
  return false;
}

void set_req_state_err(struct rgw_err& err,	/* out */
			int err_no,		/* in  */
			const int prot_flags)	/* in  */
{
  if (err_no < 0)
    err_no = -err_no;

  err.ret = -err_no;

#ifdef WITH_BCEBOS
  if (prot_flags & RGW_REST_BOS) {
    if (search_err(rgw_http_bos_errors, err_no, err.http_ret, err.err_code, err.message))
      return;
  }
#endif

  if (prot_flags & RGW_REST_SWIFT) {
    if (search_err(rgw_http_swift_errors, err_no, err.http_ret, err.err_code))
      return;
  }

  //Default to searching in s3 errors
  if (search_err(rgw_http_s3_errors, err_no, err.http_ret, err.err_code))
      return;
  dout(0) << "WARNING: set_req_state_err err_no=" << err_no
	<< " resorting to 500" << dendl;

  err.http_ret = 500;
  err.err_code = "UnknownError";
}

void set_req_state_err(struct req_state* s, int err_no, const string& err_msg)
{
  if (s) {
    set_req_state_err(s, err_no);
    if (s->prot_flags & RGW_REST_SWIFT && !err_msg.empty()) {
      /* TODO(rzarzynski): there never ever should be a check like this one.
       * It's here only for the sake of the patch's backportability. Further
       * commits will move the logic to a per-RGWHandler replacement of
       * the end_header() function. Alternativaly, we might consider making
       * that just for the dump(). Please take a look on @cbodley's comments
       * in PR #10690 (https://github.com/ceph/ceph/pull/10690). */
      s->err.err_code = err_msg;
    } else {
      s->err.message = err_msg;
    }
  }
}

void set_req_state_err(struct req_state* s, int err_no)
{
  if (s) {
    set_req_state_err(s->err, err_no, s->prot_flags);
  }
}

void dump(struct req_state* s)
{
#ifdef WITH_BCEBOS
  if (s->prot_flags & RGW_REST_BOS) {
    s->formatter->open_object_section("Error");
    if (!s->err.err_code.empty())
      s->formatter->dump_string("code", s->err.err_code);
    if (!s->err.message.empty())
      s->formatter->dump_string("message", s->err.message);
    if (!s->trans_id.empty())
      s->formatter->dump_string("requestId", s->trans_id);
    s->formatter->close_section();
  } else
#endif
  {
    if (s->format != RGW_FORMAT_HTML)
      s->formatter->open_object_section("Error");
    if (!s->err.err_code.empty())
      s->formatter->dump_string("Code", s->err.err_code);
    if (!s->err.message.empty())
      s->formatter->dump_string("Message", s->err.message);
    if (!s->bucket_name.empty())  // TODO: connect to expose_bucket
      s->formatter->dump_string("BucketName", s->bucket_name);
    if (!s->trans_id.empty()) // TODO: connect to expose_bucket or another toggle
      s->formatter->dump_string("RequestId", s->trans_id);
    s->formatter->dump_string("HostId", s->host_id);
    if (s->format != RGW_FORMAT_HTML)
      s->formatter->close_section();
  }
}

struct str_len {
  const char *str;
  int len;
};

#define STR_LEN_ENTRY(s) { s, sizeof(s) - 1 }

struct str_len meta_prefixes[] = { STR_LEN_ENTRY("HTTP_X_AMZ"),
                                   STR_LEN_ENTRY("HTTP_X_GOOG"),
                                   STR_LEN_ENTRY("HTTP_X_DHO"),
                                   STR_LEN_ENTRY("HTTP_X_RGW"),
                                   STR_LEN_ENTRY("HTTP_X_BCE"),
                                   STR_LEN_ENTRY("HTTP_X_OBJECT"),
                                   STR_LEN_ENTRY("HTTP_X_CONTAINER"),
                                   STR_LEN_ENTRY("HTTP_X_ACCOUNT"),
                                   {NULL, 0} };

void req_info::init_meta_info(bool *found_bad_meta)
{
  x_meta_map.clear();

  for (const auto& kv: env->get_map()) {
    const char *prefix;
    const string& header_name = kv.first;
    const string& val = kv.second;
    for (int prefix_num = 0; (prefix = meta_prefixes[prefix_num].str) != NULL; prefix_num++) {
      int len = meta_prefixes[prefix_num].len;
      const char *p = header_name.c_str();
      if (strncmp(p, prefix, len) == 0) {
        const char *name = p+len; /* skip the prefix */
        int name_len = header_name.size() - len;

        if (found_bad_meta && strncmp(name, "_META_", name_len) == 0)
          *found_bad_meta = true;

        char name_low[meta_prefixes[0].len + name_len + 1];
        snprintf(name_low, meta_prefixes[0].len - 5 + name_len + 1, "%s%s", meta_prefixes[0].str + 5 /* skip HTTP_ */, name); // normalize meta prefix
        int j;
        for (j = 0; name_low[j]; j++) {
          if (name_low[j] == '_') {
            name_low[j] = '-';
          } else if(name_low[j] == '-') {
            name_low[j] = '_';
          } else {
            name_low[j] = tolower(name_low[j]);
          }
        }
        name_low[j] = 0;
        auto it = x_meta_map.find(name_low);
        if (it != x_meta_map.end()) {
          string old = it->second;
          boost::algorithm::trim_right(old);
          old.append(",");
          old.append(val);
          x_meta_map[name_low] = old;
        } else {
          x_meta_map[name_low] = val;
        }
#ifdef WITH_BCEBOS
        if (strncmp("HTTP_X_BCE", prefix, len) == 0) {
          continue;
        }
        it = x_exclude_bce_meta_map.find(name_low);
        if (it != x_exclude_bce_meta_map.end()) {
          string old = it->second;
          boost::algorithm::trim_right(old);
          old.append(",");
          old.append(val);
          x_exclude_bce_meta_map[name_low] = old;
        } else {
          x_exclude_bce_meta_map[name_low] = val;
        }
#endif
      }
    }
  }
}

std::ostream& operator<<(std::ostream& oss, const rgw_err &err)
{
  oss << "rgw_err(http_ret=" << err.http_ret << ", err_code='" << err.err_code << "') ";
  return oss;
}

string rgw_string_unquote(const string& s)
{
  if (s[0] != '"' || s.size() < 2)
    return s;

  int len;
  for (len = s.size(); len > 2; --len) {
    if (s[len - 1] != ' ')
      break;
  }

  if (s[len-1] != '"')
    return s;

  return s.substr(1, len - 2);
}

static bool check_str_end(const char *s)
{
  if (!s)
    return false;

  while (*s) {
    if (!isspace(*s))
      return false;
    s++;
  }
  return true;
}

static bool check_gmt_end(const char *s)
{
  if (!s || !*s)
    return false;

  while (isspace(*s)) {
    ++s;
  }

  /* check for correct timezone */
  if ((strncmp(s, "GMT", 3) != 0) &&
      (strncmp(s, "UTC", 3) != 0)) {
    return false;
  }

  return true;
}

static bool parse_rfc850(const char *s, struct tm *t)
{
  memset(t, 0, sizeof(*t));
  return check_gmt_end(strptime(s, "%A, %d-%b-%y %H:%M:%S ", t));
}

static bool parse_asctime(const char *s, struct tm *t)
{
  memset(t, 0, sizeof(*t));
  return check_str_end(strptime(s, "%a %b %d %H:%M:%S %Y", t));
}

static bool parse_rfc1123(const char *s, struct tm *t)
{
  memset(t, 0, sizeof(*t));
  return check_gmt_end(strptime(s, "%a, %d %b %Y %H:%M:%S ", t));
}

static bool parse_rfc1123_alt(const char *s, struct tm *t)
{
  memset(t, 0, sizeof(*t));
  return check_str_end(strptime(s, "%a, %d %b %Y %H:%M:%S %z", t));
}

bool parse_rfc2616(const char *s, struct tm *t)
{
  return parse_rfc850(s, t) || parse_asctime(s, t) || parse_rfc1123(s, t) || parse_rfc1123_alt(s,t);
}

bool parse_iso8601(const char *s, struct tm *t, uint32_t *pns, bool extended_format)
{
  memset(t, 0, sizeof(*t));
  const char *p;

  if (!s)
    s = "";

  if (extended_format) {
    p = strptime(s, "%Y-%m-%dT%T", t);
    if (!p) {
      p = strptime(s, "%Y-%m-%d %T", t);
    }
  } else {
    p = strptime(s, "%Y%m%dT%H%M%S", t);
  }
  if (!p) {
    dout(0) << "parse_iso8601 failed" << dendl;
    return false;
  }
  const boost::string_view str = rgw_trim_whitespace(boost::string_view(p));
  int len = str.size();

  if (len == 0 || (len == 1 && str[0] == 'Z'))
    return true;

  if (str[0] != '.' ||
      str[len - 1] != 'Z')
    return false;

  uint32_t ms;
  boost::string_view nsstr = str.substr(1,  len - 2);
  int r = stringtoul(nsstr.to_string(), &ms);
  if (r < 0)
    return false;

  if (!pns) {
    return true;
  }

  if (nsstr.size() > 9) {
    nsstr = nsstr.substr(0, 9);
  }

  uint64_t mul_table[] = { 0,
    100000000LL,
    10000000LL,
    1000000LL,
    100000LL,
    10000LL,
    1000LL,
    100LL,
    10LL,
    1 };


  *pns = ms * mul_table[nsstr.size()];

  return true;
}

int parse_key_value(string& in_str, const char *delim, string& key, string& val)
{
  if (delim == NULL)
    return -EINVAL;

  auto pos = in_str.find(delim);
  if (pos == string::npos)
    return -EINVAL;

  key = rgw_trim_whitespace(in_str.substr(0, pos));
  val = rgw_trim_whitespace(in_str.substr(pos + 1));

  return 0;
}

int parse_key_value(string& in_str, string& key, string& val)
{
  return parse_key_value(in_str, "=", key,val);
}

boost::optional<std::pair<boost::string_view, boost::string_view>>
parse_key_value(const boost::string_view& in_str,
                const boost::string_view& delim)
{
  const size_t pos = in_str.find(delim);
  if (pos == boost::string_view::npos) {
    return boost::none;
  }

  const auto key = rgw_trim_whitespace(in_str.substr(0, pos));
  const auto val = rgw_trim_whitespace(in_str.substr(pos + 1));

  return std::make_pair(key, val);
}

boost::optional<std::pair<boost::string_view, boost::string_view>>
parse_key_value(const boost::string_view& in_str)
{
  return parse_key_value(in_str, "=");
}

int parse_time(const char *time_str, real_time *time)
{
  struct tm tm;
  uint32_t ns = 0;

  if (!parse_rfc2616(time_str, &tm) && !parse_iso8601(time_str, &tm, &ns)) {
    return -EINVAL;
  }

  time_t sec = internal_timegm(&tm);
  *time = utime_t(sec, ns).to_real_time();

  return 0;
}

#define TIME_BUF_SIZE 128
void rgw_to_iso8601(const real_time& t, char *dest, int buf_size)
{
  utime_t ut(t);

  char buf[TIME_BUF_SIZE];
  struct tm result;
  time_t epoch = ut.sec();
  struct tm *tmp = gmtime_r(&epoch, &result);
  if (tmp == NULL)
    return;

  if (strftime(buf, sizeof(buf), "%Y-%m-%dT%T", tmp) == 0)
    return;
#ifdef WITH_BCEBOS
  snprintf(dest, buf_size, "%sZ", buf);
#else
  snprintf(dest, buf_size, "%s.%03dZ", buf, (int)(ut.usec() / 1000));
#endif
}

void rgw_to_iso8601(const real_time& t, string *dest)
{
  char buf[TIME_BUF_SIZE];
  rgw_to_iso8601(t, buf, sizeof(buf));
  *dest = buf;
}


string rgw_to_asctime(const utime_t& t)
{
  stringstream s;
  t.asctime(s);
  return s.str();
}

/*
 * calculate the sha1 value of a given msg and key
 */
void calc_hmac_sha1(const char *key, int key_len,
                    const char *msg, int msg_len, char *dest)
/* destination should be CEPH_CRYPTO_HMACSHA1_DIGESTSIZE bytes long */
{
  HMACSHA1 hmac((const unsigned char *)key, key_len);
  hmac.Update((const unsigned char *)msg, msg_len);
  hmac.Final((unsigned char *)dest);
}

/*
 * calculate the sha256 value of a given msg and key
 */
void calc_hmac_sha256(const char *key, int key_len,
                      const char *msg, int msg_len, char *dest)
{
  char hash_sha256[CEPH_CRYPTO_HMACSHA256_DIGESTSIZE];

  HMACSHA256 hmac((const unsigned char *)key, key_len);
  hmac.Update((const unsigned char *)msg, msg_len);
  hmac.Final((unsigned char *)hash_sha256);

  memcpy(dest, hash_sha256, CEPH_CRYPTO_HMACSHA256_DIGESTSIZE);
}

using ceph::crypto::SHA256;

/*
 * calculate the sha256 hash value of a given msg
 */
sha256_digest_t calc_hash_sha256(const boost::string_view& msg)
{
  std::array<unsigned char, CEPH_CRYPTO_HMACSHA256_DIGESTSIZE> hash;

  ceph::crypto::SHA256 hasher;
  hasher.Update(reinterpret_cast<const unsigned char*>(msg.data()), msg.size());
  hasher.Final(hash.data());

  return hash;
}

ceph::crypto::SHA256* calc_hash_sha256_open_stream()
{
  return new ceph::crypto::SHA256;
}

void calc_hash_sha256_update_stream(ceph::crypto::SHA256 *hash, const char *msg, int len)
{
  hash->Update((const unsigned char *)msg, len);
}

string calc_hash_sha256_close_stream(ceph::crypto::SHA256 **phash)
{
  ceph::crypto::SHA256 *hash = *phash;
  if (!hash) {
    hash = calc_hash_sha256_open_stream();
  }
  char hash_sha256[CEPH_CRYPTO_HMACSHA256_DIGESTSIZE];

  hash->Final((unsigned char *)hash_sha256);

  char hex_str[(CEPH_CRYPTO_SHA256_DIGESTSIZE * 2) + 1];
  buf_to_hex((unsigned char *)hash_sha256, CEPH_CRYPTO_SHA256_DIGESTSIZE, hex_str);

  delete hash;
  *phash = NULL;
  
  return std::string(hex_str);
}

std::string calc_hash_sha256_restart_stream(ceph::crypto::SHA256 **phash)
{
  const auto hash = calc_hash_sha256_close_stream(phash);
  *phash = calc_hash_sha256_open_stream();

  return hash;
}

int gen_rand_base64(CephContext *cct, char *dest, int size) /* size should be the required string size + 1 */
{
  char buf[size];
  char tmp_dest[size + 4]; /* so that there's space for the extra '=' characters, and some */
  int ret;

  cct->random()->get_bytes(buf, sizeof(buf));

  ret = ceph_armor(tmp_dest, &tmp_dest[sizeof(tmp_dest)],
		   (const char *)buf, ((const char *)buf) + ((size - 1) * 3 + 4 - 1) / 4);
  if (ret < 0) {
    lderr(cct) << "ceph_armor failed" << dendl;
    return ret;
  }
  tmp_dest[ret] = '\0';
  memcpy(dest, tmp_dest, size);
  dest[size-1] = '\0';

  return 0;
}

static const char alphanum_upper_table[]="0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ";

void gen_rand_alphanumeric_upper(CephContext *cct, char *dest, int size) /* size should be the required string size + 1 */
{
  cct->random()->get_bytes(dest, size);

  int i;
  for (i=0; i<size - 1; i++) {
    int pos = (unsigned)dest[i];
    dest[i] = alphanum_upper_table[pos % (sizeof(alphanum_upper_table) - 1)];
  }
  dest[i] = '\0';
}

static const char alphanum_lower_table[]="0123456789abcdefghijklmnopqrstuvwxyz";

void gen_rand_alphanumeric_lower(CephContext *cct, char *dest, int size) /* size should be the required string size + 1 */
{
  cct->random()->get_bytes(dest, size);

  int i;
  for (i=0; i<size - 1; i++) {
    int pos = (unsigned)dest[i];
    dest[i] = alphanum_lower_table[pos % (sizeof(alphanum_lower_table) - 1)];
  }
  dest[i] = '\0';
}

void gen_rand_alphanumeric_lower(CephContext *cct, string *str, int length)
{
  char buf[length + 1];
  gen_rand_alphanumeric_lower(cct, buf, sizeof(buf));
  *str = buf;
}

// this is basically a modified base64 charset, url friendly
static const char alphanum_table[]="ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

void gen_rand_alphanumeric(CephContext *cct, char *dest, int size) /* size should be the required string size + 1 */
{
  cct->random()->get_bytes(dest, size);

  int i;
  for (i=0; i<size - 1; i++) {
    int pos = (unsigned)dest[i];
    dest[i] = alphanum_table[pos & 63];
  }
  dest[i] = '\0';
}

static const char alphanum_no_underscore_table[]="ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-.";

void gen_rand_alphanumeric_no_underscore(CephContext *cct, char *dest, int size) /* size should be the required string size + 1 */
{
  cct->random()->get_bytes(dest, size);

  int i;
  for (i=0; i<size - 1; i++) {
    int pos = (unsigned)dest[i];
    dest[i] = alphanum_no_underscore_table[pos & 63];
  }
  dest[i] = '\0';
}

static const char alphanum_plain_table[]="ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";

void gen_rand_alphanumeric_plain(CephContext *cct, char *dest, int size) /* size should be the required string size + 1 */
{
  cct->random()->get_bytes(dest, size);

  int i;
  for (i=0; i<size - 1; i++) {
    int pos = (unsigned)dest[i];
    dest[i] = alphanum_plain_table[pos % (sizeof(alphanum_plain_table) - 1)];
  }
  dest[i] = '\0';
}

int NameVal::parse()
{
  auto delim_pos = str.find('=');
  int ret = 0;

  if (delim_pos == string::npos) {
    name = str;
    val = "";
    ret = 1;
  } else {
    name = str.substr(0, delim_pos);
    val = str.substr(delim_pos + 1);
  }

  return ret; 
}

int RGWHTTPArgs::parse()
{
  int pos = 0;
  bool end = false;

  if (str.empty())
    return 0;

  if (str[pos] == '?')
    pos++;

  while (!end) {
    int fpos = str.find('&', pos);
    if (fpos  < pos) {
       end = true;
       fpos = str.size(); 
    }
    std::string nameval = url_decode(str.substr(pos, fpos - pos), true);
    NameVal nv(std::move(nameval));
    int ret = nv.parse();
    if (ret >= 0) {
      string& name = nv.get_name();
      string& val = nv.get_val();

      append(name, val);
    }

    pos = fpos + 1;  
  }

  return 0;
}

void RGWHTTPArgs::append(const string& name, const string& val)
{
  if (name.compare(0, sizeof(RGW_SYS_PARAM_PREFIX) - 1, RGW_SYS_PARAM_PREFIX) == 0) {
    sys_val_map[name] = val;
  } else {
    val_map[name] = val;
  }

  if ((name.compare("acl") == 0) ||
      (name.compare("cors") == 0) ||
      (name.compare("location") == 0) ||
      (name.compare("logging") == 0) ||
      (name.compare("usage") == 0) ||
      (name.compare("lifecycle") == 0) ||
      (name.compare("delete") == 0) ||
      (name.compare("uploads") == 0) ||
      (name.compare("partNumber") == 0) ||
      (name.compare("uploadId") == 0) ||
      (name.compare("versionId") == 0) ||
      (name.compare("start-date") == 0) ||
      (name.compare("end-date") == 0) ||
      (name.compare("versions") == 0) ||
      (name.compare("versioning") == 0) ||
      (name.compare("website") == 0) ||
      (name.compare("namespace") == 0) ||
      (name.compare("requestPayment") == 0) ||
      (name.compare("torrent") == 0) ||
      (name.compare("tagging") == 0) ||
      (name.compare("style") == 0) ||
      (name.compare("styles") == 0) ||
      (name.compare("copyrightProtection") == 0) ||
      (name.compare("notification") == 0) ||
      (name.compare("read-usage") == 0) ||
      (name.compare("multisite-dataflow") == 0)) {
    sub_resources[name] = val;
  } else if (name[0] == 'r') { // root of all evil
    if ((name.compare("response-content-type") == 0) ||
        (name.compare("response-content-language") == 0) ||
        (name.compare("response-expires") == 0) ||
        (name.compare("response-cache-control") == 0) ||
        (name.compare("response-content-disposition") == 0) ||
        (name.compare("response-content-encoding") == 0)) {
      sub_resources[name] = val;
      has_resp_modifier = true;
    }
  } else if  ((name.compare("subuser") == 0) ||
              (name.compare("key") == 0) ||
              (name.compare("caps") == 0) ||
              (name.compare("index") == 0) ||
              (name.compare("policy") == 0) ||
              (name.compare("quota") == 0) ||
              (name.compare("qos") == 0) ||
              (name.compare("list") == 0) ||
              (name.compare("syncstatus") == 0) ||
              (name.compare("object") == 0)) {

    if (!admin_subresource_added) {
      sub_resources[name] = "";
      admin_subresource_added = true;
    }
  }
}

const string& RGWHTTPArgs::get(const string& name, bool *exists) const
{
  auto iter = val_map.find(name);
  bool e = (iter != std::end(val_map));
  if (exists)
    *exists = e;
  if (e)
    return iter->second;
  return empty_str;
}

boost::optional<const std::string&>
RGWHTTPArgs::get_optional(const std::string& name) const
{
  bool exists;
  const std::string& value = get(name, &exists);
  if (exists) {
    return value;
  } else {
    return boost::none;
  }
}

int RGWHTTPArgs::get_bool(const string& name, bool *val, bool *exists)
{
  map<string, string>::iterator iter;
  iter = val_map.find(name);
  bool e = (iter != val_map.end());
  if (exists)
    *exists = e;

  if (e) {
    const char *s = iter->second.c_str();

    if (strcasecmp(s, "false") == 0) {
      *val = false;
    } else if (strcasecmp(s, "true") == 0) {
      *val = true;
    } else {
      return -EINVAL;
    }
  }

  return 0;
}

int RGWHTTPArgs::get_bool(const char *name, bool *val, bool *exists)
{
  string s(name);
  return get_bool(s, val, exists);
}

void RGWHTTPArgs::get_bool(const char *name, bool *val, bool def_val)
{
  bool exists = false;
  if ((get_bool(name, val, &exists) < 0) ||
      !exists) {
    *val = def_val;
  }
}

int RGWHTTPArgs::get_int(const char *name, int *val, int def_val) const
{
  bool exists = false;
  string val_str;
  val_str = get(name, &exists);
  if (!exists) {
    *val = def_val;
    return 0;
  }

  string err;

  *val = (int)strict_strtol(val_str.c_str(), 10, &err);
  if (!err.empty()) {
    *val = def_val;
    return -EINVAL;
  }
  return 0;
}

string RGWHTTPArgs::sys_get(const string& name, bool * const exists) const
{
  const auto iter = sys_val_map.find(name);
  const bool e = (iter != sys_val_map.end());

  if (exists) {
    *exists = e;
  }

  return e ? iter->second : string();
}

bool rgw_transport_is_secure(CephContext *cct, const RGWEnv& env)
{
  const auto& m = env.get_map();
  // frontend connected with ssl
  if (m.count("SERVER_PORT_SECURE")) {
    return true;
  }
  // ignore proxy headers unless explicitly enabled
  if (!cct->_conf->rgw_trust_forwarded_https) {
    return false;
  }
  // https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Forwarded
  // Forwarded: by=<identifier>; for=<identifier>; host=<host>; proto=<http|https>
  auto i = m.find("HTTP_FORWARDED");
  if (i != m.end() && i->second.find("proto=https") != std::string::npos) {
    return true;
  }
  // https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Forwarded-Proto
  i = m.find("HTTP_X_FORWARDED_PROTO");
  if (i != m.end() && i->second == "https") {
    return true;
  }
  return false;
}

bool verify_user_permission(struct req_state * const s,
                            RGWAccessControlPolicy * const user_acl,
                            const int perm)
{
  /* S3 doesn't support account ACLs. */
  if (!user_acl)
    return true;

  if ((perm & (int)s->perm_mask) != perm)
    return false;

  return user_acl->verify_permission(*s->auth.identity, perm, perm);
}

bool verify_user_permission(struct req_state * const s,
                            const int perm)
{
  return verify_user_permission(s, s->user_acl.get(), perm);
}

bool verify_requester_payer_permission(struct req_state *s)
{
  if (!s->bucket_info.requester_pays)
    return true;

  if (s->auth.identity->is_owner_of(s->bucket_info.owner))
    return true;
  
  if (s->auth.identity->is_anonymous()) {
    return false;
  }

  const char *request_payer = s->info.env->get("HTTP_X_AMZ_REQUEST_PAYER");
  if (!request_payer) {
    bool exists;
    request_payer = s->info.args.get("x-amz-request-payer", &exists).c_str();
    if (!exists) {
      return false;
    }
  }

  if (strcasecmp(request_payer, "requester") == 0) {
    return true;
  }

  return false;
}

namespace {
Effect eval_or_pass(const boost::optional<Policy>& policy,
		    const rgw::IAM::Environment& env,
		    const rgw::auth::Identity& id,
		    const uint64_t op,
		    const ARN& arn) {
  if (!policy)
    return Effect::Pass;
  else
    return policy->eval(env, id, op, arn);
}
}

bool verify_bucket_permission(struct req_state * const s,
			      const rgw_bucket& bucket,
                              RGWAccessControlPolicy * const user_acl,
                              RGWAccessControlPolicy * const bucket_acl,
			      const boost::optional<Policy>& bucket_policy,
                              const uint64_t op)
{
  if (!verify_requester_payer_permission(s))
    return false;

  auto r = eval_or_pass(bucket_policy, s->env, *s->auth.identity,
			op, ARN(bucket));
  if (r == Effect::Allow) {
    // It looks like S3 ACLs only GRANT permissions rather than
    // denying them, so this should be safe.
    return true;
  } else if (r == Effect::Deny) {
    return false;
  }

  const auto perm = op_to_perm(op);

  return verify_bucket_permission_no_policy(s, user_acl, bucket_acl, perm);
}

bool verify_bucket_permission_no_policy(struct req_state * const s,
					RGWAccessControlPolicy * const user_acl,
					RGWAccessControlPolicy * const bucket_acl,
					const int perm)
{
  if (!bucket_acl)
    return false;

  if ((perm & (int)s->perm_mask) != perm)
    return false;

  if (bucket_acl->verify_permission(*s->auth.identity, perm, perm,
                                    s->info.env->get("HTTP_REFERER")))
    return true;

  if (!user_acl)
    return false;

  return user_acl->verify_permission(*s->auth.identity, perm, perm);
}

bool verify_bucket_permission_no_policy(struct req_state * const s, const int perm)
{
  if (!verify_requester_payer_permission(s))
    return false;

  return verify_bucket_permission_no_policy(s,
                                            s->user_acl.get(),
                                            s->bucket_acl.get(),
                                            perm);
}

bool verify_bucket_permission(struct req_state * const s, const uint64_t op)
{
  return verify_bucket_permission(s,
                                  s->bucket,
                                  s->user_acl.get(),
                                  s->bucket_acl.get(),
                                  s->iam_policy,
                                  op);
}

// Authorize anyone permitted by the policy and the bucket owner
// unless explicitly denied by the policy.

int verify_bucket_owner_or_policy(struct req_state* const s,
				  const uint64_t op)
{
  auto e = eval_or_pass(s->iam_policy,
			s->env, *s->auth.identity,
			op, ARN(s->bucket));
  if (e == Effect::Allow ||
      (e == Effect::Pass &&
       s->auth.identity->is_owner_of(s->bucket_owner.get_id()))) {
    return 0;
  } else {
    return -EACCES;
  }
}


static inline bool check_deferred_bucket_perms(struct req_state * const s,
					       const rgw_bucket& bucket,
					       RGWAccessControlPolicy * const user_acl,
					       RGWAccessControlPolicy * const bucket_acl,
					       const boost::optional<Policy>& bucket_policy,
					       const uint8_t deferred_check,
					       const uint64_t op)
{
  return (s->defer_to_bucket_acls == deferred_check \
	  && verify_bucket_permission(s, bucket, user_acl, bucket_acl, bucket_policy, op));
}

static inline bool check_deferred_bucket_only_acl(struct req_state * const s,
						  RGWAccessControlPolicy * const user_acl,
						  RGWAccessControlPolicy * const bucket_acl,
						  const uint8_t deferred_check,
						  const int perm)
{
  return (s->defer_to_bucket_acls == deferred_check \
	  && verify_bucket_permission_no_policy(s, user_acl, bucket_acl, perm));
}

bool verify_object_permission(struct req_state * const s,
                              const rgw_obj& obj,
                              RGWAccessControlPolicy * const user_acl,
                              RGWAccessControlPolicy * const bucket_acl,
                              RGWAccessControlPolicy * const object_acl,
                              const boost::optional<Policy>& bucket_policy,
                              const uint64_t op)
{
  if (!verify_requester_payer_permission(s))
    return false;

#ifdef WITH_BCEBOS
  if (!(s->prot_flags & RGW_REST_BOS) || (object_acl && s->object_acl->is_obj_same_with_bucket_acl()))
#endif
  {
    auto r = eval_or_pass(bucket_policy, s->env, *s->auth.identity, op, ARN(obj));
    if (r == Effect::Allow)
      // It looks like S3 ACLs only GRANT permissions rather than
      // denying them, so this should be safe.
      return true;
    else if (r == Effect::Deny)
      return false;
    if (check_deferred_bucket_perms(s, obj.bucket, user_acl, bucket_acl, bucket_policy,
                                    RGW_DEFER_TO_BUCKET_ACLS_RECURSE, op) ||
        check_deferred_bucket_perms(s, obj.bucket, user_acl, bucket_acl, bucket_policy,
                                    RGW_DEFER_TO_BUCKET_ACLS_FULL_CONTROL, rgw::IAM::s3All)) {
      return true;
    }
  }

  if (!object_acl) {
    return false;
  }

  const auto perm = op_to_perm(op);
  bool ret = object_acl->verify_permission(*s->auth.identity, s->perm_mask, perm);
  if (ret) {
    return true;
  }

  if (!s->cct->_conf->rgw_enforce_swift_acls) {
    return ret;
  }

  if ((perm & (int)s->perm_mask) != perm) {
    return false;
  }

  /*int swift_perm = 0;
  if (perm & (RGW_PERM_READ | RGW_PERM_READ_ACP))
    swift_perm |= RGW_PERM_READ_OBJS;
  if (perm & RGW_PERM_WRITE)
    swift_perm |= RGW_PERM_WRITE_OBJS;

  if (!swift_perm)
    return false;*/

  /* we already verified the user mask above, so we pass swift_perm as the mask here,
     otherwise the mask might not cover the swift permissions bits */
#ifdef WITH_BCEBOS
  if (!(s->prot_flags & RGW_REST_BOS) || s->object_acl->is_obj_same_with_bucket_acl())
#endif
  {
    if (bucket_acl->verify_permission(*s->auth.identity, perm, perm,
                                    s->info.env->get("HTTP_REFERER"))) {
      return true;
    }
  }

  if (!user_acl)
    return false;

  return user_acl->verify_permission(*s->auth.identity, perm, perm);
}

bool verify_object_permission_no_policy(struct req_state * const s,
                                        RGWAccessControlPolicy * const user_acl,
                                        RGWAccessControlPolicy * const bucket_acl,
                                        RGWAccessControlPolicy * const object_acl,
                                        const int perm)
{
#ifdef WITH_BCEBOS
  if (!(s->prot_flags & RGW_REST_BOS) || (s->object_acl && s->object_acl->is_obj_same_with_bucket_acl()))
#endif
  {
    if (check_deferred_bucket_only_acl(s, user_acl, bucket_acl, RGW_DEFER_TO_BUCKET_ACLS_RECURSE, perm) ||
        check_deferred_bucket_only_acl(s, user_acl, bucket_acl, RGW_DEFER_TO_BUCKET_ACLS_FULL_CONTROL, RGW_PERM_FULL_CONTROL)) {
      return true;
    }
  }
  if (!object_acl) {
    return false;
  }

  bool ret = object_acl->verify_permission(*s->auth.identity, s->perm_mask, perm);
  if (ret) {
    return true;
  }

  if (!s->cct->_conf->rgw_enforce_swift_acls)
    return ret;

  if ((perm & (int)s->perm_mask) != perm)
    return false;

  /*int swift_perm = 0;
  if (perm & (RGW_PERM_READ | RGW_PERM_READ_ACP))
    swift_perm |= RGW_PERM_READ_OBJS;
  if (perm & RGW_PERM_WRITE)
    swift_perm |= RGW_PERM_WRITE_OBJS;

  if (!swift_perm)
    return false;*/

  /* we already verified the user mask above, so we pass swift_perm as the mask here,
     otherwise the mask might not cover the swift permissions bits */
  if (bucket_acl->verify_permission(*s->auth.identity, perm, perm,
                                    s->info.env->get("HTTP_REFERER"))) {
    return true;
  }
  if (!user_acl)
    return false;

  return user_acl->verify_permission(*s->auth.identity, perm, perm);
}

bool verify_object_permission_no_policy(struct req_state *s, int perm)
{
  if (!verify_requester_payer_permission(s))
    return false;

  return verify_object_permission_no_policy(s,
                                            s->user_acl.get(),
                                            s->bucket_acl.get(),
                                            s->object_acl.get(),
                                            perm);
}

bool verify_object_permission(struct req_state *s, uint64_t op)
{
  return verify_object_permission(s,
                                  rgw_obj(s->bucket, s->object),
                                  s->user_acl.get(),
                                  s->bucket_acl.get(),
                                  s->object_acl.get(),
                                  s->iam_policy,
                                  op);
}

bool verify_object_permission(struct req_state *s, uint64_t op, rgw_obj_key& obj)
{
  return verify_object_permission(s,
                                  rgw_obj(s->bucket, obj),
                                  s->user_acl.get(),
                                  s->bucket_acl.get(),
                                  s->object_acl.get(),
                                  s->iam_policy,
                                  op);
}

class HexTable
{
  char table[256];

public:
  HexTable() {
    memset(table, -1, sizeof(table));
    int i;
    for (i = '0'; i<='9'; i++)
      table[i] = i - '0';
    for (i = 'A'; i<='F'; i++)
      table[i] = i - 'A' + 0xa;
    for (i = 'a'; i<='f'; i++)
      table[i] = i - 'a' + 0xa;
  }

  char to_num(char c) {
    return table[(int)c];
  }
};

static char hex_to_num(char c)
{
  static HexTable hex_table;
  return hex_table.to_num(c);
}

std::string url_decode(const boost::string_view& src_str, bool in_query)
{
  std::string dest_str;
  dest_str.reserve(src_str.length() + 1);

  for (auto src = std::begin(src_str); src != std::end(src_str); ++src) {
    if (*src != '%') {
      if (!in_query || *src != '+') {
        if (*src == '?') {
          in_query = true;
        }
        dest_str.push_back(*src);
      } else {
        dest_str.push_back(' ');
      }
    } else {
      /* 3 == strlen("%%XX") */
      if (std::distance(src, std::end(src_str)) < 3) {
        break;
      }

      src++;
      const char c1 = hex_to_num(*src++);
      const char c2 = hex_to_num(*src);
      if (c1 < 0 || c2 < 0) {
        return std::string();
      } else {
        dest_str.push_back(c1 << 4 | c2);
      }
    }
  }

  return dest_str;
}

void rgw_uri_escape_char(char c, string& dst)
{
  char buf[16];
  snprintf(buf, sizeof(buf), "%%%.2X", (int)(unsigned char)c);
  dst.append(buf);
}

static bool char_needs_url_encoding(char c)
{
  if (c <= 0x20 || c >= 0x7f)
    return true;
  switch (c) {
    case 0x22:
    case 0x23:
    case 0x25:
    case 0x26:
    case 0x2B:
    case 0x2C:
    case 0x2F:
    case 0x3A:
    case 0x3B:
    case 0x3C:
    case 0x3E:
    case 0x3D:
    case 0x3F:
    case 0x40:
    case 0x5B:
    case 0x5D:
    case 0x5C:
    case 0x5E:
    case 0x60:
    case 0x7B:
    case 0x7D:
      return true;
  }
  return false;
}

void url_encode(const string& src, string& dst, bool encode_slash)
{
  const char *p = src.c_str();
  for (unsigned i = 0; i < src.size(); i++, p++) {
    if ((!encode_slash && *p == 0x2F) || !char_needs_url_encoding(*p)) {
      dst.append(p, 1);
    }else {
      rgw_uri_escape_char(*p, dst);
    }
  }
}

std::string url_encode(const std::string& src, bool encode_slash)
{
  std::string dst;
  url_encode(src, dst, encode_slash);

  return dst;
}

string rgw_trim_whitespace(const string& src)
{
  if (src.empty()) {
    return string();
  }

  int start = 0;
  for (; start != (int)src.size(); start++) {
    if (!isspace(src[start]))
      break;
  }

  int end = src.size() - 1;
  if (end < start) {
    return string();
  }

  for (; end > start; end--) {
    if (!isspace(src[end]))
      break;
  }

  return src.substr(start, end - start + 1);
}

string rgw_trim_character(const string& src, const char& delimiter)
{
    if (src.empty()) {
    return string();
  }

  int start = 0;
  for (; start != (int)src.size(); start++) {
    if (src[start] != delimiter)
      break;
  }

  int end = src.size() - 1;
  if (end < start) {
    return string();
  }

  for (; end > start; end--) {
    if (src[end] != delimiter)
      break;
  }

  return src.substr(start, end - start + 1);
}

string rgw_trim_enter(const string& src)
{
  return rgw_trim_character(src, '\n');
}

boost::string_view rgw_trim_whitespace(const boost::string_view& src)
{
  boost::string_view res = src;

  while (res.size() > 0 && std::isspace(res.front())) {
    res.remove_prefix(1);
  }
  while (res.size() > 0 && std::isspace(res.back())) {
    res.remove_suffix(1);
  }
  return res;
}

string rgw_trim_quotes(const string& val)
{
  string s = rgw_trim_whitespace(val);
  if (s.size() < 2)
    return s;

  int start = 0;
  int end = s.size() - 1;
  int quotes_count = 0;

  if (s[start] == '"') {
    start++;
    quotes_count++;
  }
  if (s[end] == '"') {
    end--;
    quotes_count++;
  }
  if (quotes_count == 2) {
    return s.substr(start, end - start + 1);
  }
  return s;
}

struct rgw_name_to_flag {
  const char *type_name;
  uint32_t flag;
};

static int parse_list_of_flags(struct rgw_name_to_flag *mapping,
                               const string& str, uint32_t *perm)
{
  list<string> strs;
  get_str_list(str, strs);
  list<string>::iterator iter;
  uint32_t v = 0;
  for (iter = strs.begin(); iter != strs.end(); ++iter) {
    string& s = *iter;
    for (int i = 0; mapping[i].type_name; i++) {
      if (s.compare(mapping[i].type_name) == 0)
        v |= mapping[i].flag;
    }
  }

  *perm = v;
  return 0;
}

static struct rgw_name_to_flag cap_names[] = { {"*",     RGW_CAP_ALL},
                  {"read",  RGW_CAP_READ},
		  {"write", RGW_CAP_WRITE},
		  {NULL, 0} };

int RGWUserCaps::parse_cap_perm(const string& str, uint32_t *perm)
{
  return parse_list_of_flags(cap_names, str, perm);
}

int RGWUserCaps::get_cap(const string& cap, string& type, uint32_t *pperm)
{
  int pos = cap.find('=');
  if (pos >= 0) {
    type = rgw_trim_whitespace(cap.substr(0, pos));
  }

  if (!is_valid_cap_type(type))
    return -ERR_INVALID_CAP;

  string cap_perm;
  uint32_t perm = 0;
  if (pos < (int)cap.size() - 1) {
    cap_perm = cap.substr(pos + 1);
    int r = RGWUserCaps::parse_cap_perm(cap_perm, &perm);
    if (r < 0)
      return r;
  }

  *pperm = perm;

  return 0;
}

int RGWUserCaps::add_cap(const string& cap)
{
  uint32_t perm;
  string type;

  int r = get_cap(cap, type, &perm);
  if (r < 0)
    return r;

  caps[type] |= perm;

  return 0;
}

int RGWUserCaps::remove_cap(const string& cap)
{
  uint32_t perm;
  string type;

  int r = get_cap(cap, type, &perm);
  if (r < 0)
    return r;

  map<string, uint32_t>::iterator iter = caps.find(type);
  if (iter == caps.end())
    return 0;

  uint32_t& old_perm = iter->second;
  old_perm &= ~perm;
  if (!old_perm)
    caps.erase(iter);

  return 0;
}

int RGWUserCaps::add_from_string(const string& str)
{
  int start = 0;
  do {
    auto end = str.find(';', start);
    if (end == string::npos)
      end = str.size();

    int r = add_cap(str.substr(start, end - start));
    if (r < 0)
      return r;

    start = end + 1;
  } while (start < (int)str.size());

  return 0;
}

int RGWUserCaps::remove_from_string(const string& str)
{
  int start = 0;
  do {
    auto end = str.find(';', start);
    if (end == string::npos)
      end = str.size();

    int r = remove_cap(str.substr(start, end - start));
    if (r < 0)
      return r;

    start = end + 1;
  } while (start < (int)str.size());

  return 0;
}

void RGWUserCaps::dump(Formatter *f) const
{
  dump(f, "caps");
}

void RGWUserCaps::dump(Formatter *f, const char *name) const
{
  f->open_array_section(name);
  map<string, uint32_t>::const_iterator iter;
  for (iter = caps.begin(); iter != caps.end(); ++iter)
  {
    f->open_object_section("cap");
    f->dump_string("type", iter->first);
    uint32_t perm = iter->second;
    string perm_str;
    for (int i=0; cap_names[i].type_name; i++) {
      if ((perm & cap_names[i].flag) == cap_names[i].flag) {
	if (perm_str.size())
	  perm_str.append(", ");

	perm_str.append(cap_names[i].type_name);
	perm &= ~cap_names[i].flag;
      }
    }
    if (perm_str.empty())
      perm_str = "<none>";

    f->dump_string("perm", perm_str);
    f->close_section();
  }

  f->close_section();
}

struct RGWUserCap {
  string type;
  uint32_t perm;

  void decode_json(JSONObj *obj) {
    JSONDecoder::decode_json("type", type, obj);
    string perm_str;
    JSONDecoder::decode_json("perm", perm_str, obj);
    if (RGWUserCaps::parse_cap_perm(perm_str, &perm) < 0) {
      throw JSONDecoder::err("failed to parse permissions");
    }
  }
};

void RGWUserCaps::decode_json(JSONObj *obj)
{
  list<RGWUserCap> caps_list;
  decode_json_obj(caps_list, obj);

  list<RGWUserCap>::iterator iter;
  for (iter = caps_list.begin(); iter != caps_list.end(); ++iter) {
    RGWUserCap& cap = *iter;
    caps[cap.type] = cap.perm;
  }
}

int RGWUserCaps::check_cap(const string& cap, uint32_t perm)
{
  map<string, uint32_t>::iterator iter = caps.find(cap);

  if ((iter == caps.end()) ||
      (iter->second & perm) != perm) {
    return -EPERM;
  }

  return 0;
}

bool RGWUserCaps::is_valid_cap_type(const string& tp)
{
  static const char *cap_type[] = { "user",
                                    "users",
                                    "buckets",
                                    "metadata",
                                    "usage",
                                    "zone",
                                    "bilog",
                                    "mdlog",
                                    "datalog",
                                    "opstate",
                                    "roles",
                                    "control"};

  for (unsigned int i = 0; i < sizeof(cap_type) / sizeof(char *); ++i) {
    if (tp.compare(cap_type[i]) == 0) {
      return true;
    }
  }

  return false;
}

void rgw_pool::from_str(const string& s)
{
  size_t pos = rgw_unescape_str(s, 0, '\\', ':', &name);
  if (pos != string::npos) {
    pos = rgw_unescape_str(s, pos, '\\', ':', &ns);
    /* ignore return; if pos != string::npos it means that we had a colon
     * in the middle of ns that wasn't escaped, we're going to stop there
     */
  }
}

string rgw_pool::to_str() const
{
  string esc_name;
  rgw_escape_str(name, '\\', ':', &esc_name);
  if (ns.empty()) {
    return esc_name;
  }
  string esc_ns;
  rgw_escape_str(ns, '\\', ':', &esc_ns);
  return esc_name + ":" + esc_ns;
}

void rgw_raw_obj::decode_from_rgw_obj(bufferlist::iterator& bl)
{
  using ceph::decode;
  rgw_obj old_obj;
  decode(old_obj, bl);

  get_obj_bucket_and_oid_loc(old_obj, oid, loc);
  pool = old_obj.get_explicit_data_pool();
}

std::string rgw_bucket::get_key(char tenant_delim, char id_delim, size_t reserve) const
{
  const size_t max_len = tenant.size() + sizeof(tenant_delim) +
      name.size() + sizeof(id_delim) + bucket_id.size() + reserve;

  std::string key;
  key.reserve(max_len);
  if (!tenant.empty() && tenant_delim) {
    key.append(tenant);
    key.append(1, tenant_delim);
  }
  key.append(name);
  if (!bucket_id.empty() && id_delim) {
    key.append(1, id_delim);
    key.append(bucket_id);
  }
  return key;
}

std::string rgw_bucket_shard::get_key(char tenant_delim, char id_delim,
                                      char shard_delim) const
{
  static constexpr size_t shard_len{12}; // ":4294967295\0"
  auto key = bucket.get_key(tenant_delim, id_delim, shard_len);
  if (shard_id >= 0 && shard_delim) {
    key.append(1, shard_delim);
    key.append(std::to_string(shard_id));
  }
  return key;
}

static struct rgw_name_to_flag op_type_mapping[] = { {"*",  RGW_OP_TYPE_ALL},
                  {"read",  RGW_OP_TYPE_READ},
		  {"write", RGW_OP_TYPE_WRITE},
		  {"delete", RGW_OP_TYPE_DELETE},
		  {NULL, 0} };


int rgw_parse_op_type_list(const string& str, uint32_t *perm)
{
  return parse_list_of_flags(op_type_mapping, str, perm);
}

bool match_policy(boost::string_view pattern, boost::string_view input,
                  uint32_t flag)
{
  const uint32_t flag2 = flag & (MATCH_POLICY_ACTION|MATCH_POLICY_ARN) ?
      MATCH_CASE_INSENSITIVE : 0;
  const bool colonblocks = !(flag & (MATCH_POLICY_RESOURCE |
				     MATCH_POLICY_STRING));

  const auto npos = boost::string_view::npos;
  boost::string_view::size_type last_pos_input = 0, last_pos_pattern = 0;
  while (true) {
    auto cur_pos_input = colonblocks ? input.find(":", last_pos_input) : npos;
    auto cur_pos_pattern =
      colonblocks ? pattern.find(":", last_pos_pattern) : npos;

    auto substr_input = input.substr(last_pos_input, cur_pos_input);
    auto substr_pattern = pattern.substr(last_pos_pattern, cur_pos_pattern);

    if (!match_wildcards(substr_pattern, substr_input, flag2))
      return false;

    if (cur_pos_pattern == npos)
      return cur_pos_input == npos;
    if (cur_pos_input == npos)
      return false;

    last_pos_pattern = cur_pos_pattern + 1;
    last_pos_input = cur_pos_input + 1;
  }
}

/*
 * make attrs look-like-this
 * converts underscores to dashes
 */
string lowercase_dash_http_attr(const string& orig)
{
  const char *s = orig.c_str();
  char buf[orig.size() + 1];
  buf[orig.size()] = '\0';

  for (size_t i = 0; i < orig.size(); ++i, ++s) {
    switch (*s) {
      case '_':
        buf[i] = '-';
        break;
      default:
        buf[i] = tolower(*s);
    }
  }
  return string(buf);
}

/*
 * make attrs Look-Like-This
 * converts underscores to dashes
 */
string camelcase_dash_http_attr(const string& orig)
{
  const char *s = orig.c_str();
  char buf[orig.size() + 1];
  buf[orig.size()] = '\0';

  bool last_sep = true;

  for (size_t i = 0; i < orig.size(); ++i, ++s) {
    switch (*s) {
      case '_':
      case '-':
        buf[i] = '-';
        last_sep = true;
        break;
      default:
        if (last_sep) {
          buf[i] = toupper(*s);
        } else {
          buf[i] = tolower(*s);
        }
        last_sep = false;
    }
  }
  return string(buf);
}

int ConnectionPool::find_free_socket() {
  int start = ceph::util::generate_random_number(0, _total_sock_number - 1);
  for (int i = 0; i < _total_sock_number; i++) {
    int idx = (i + start) % _total_sock_number;
    if (_sock_arr[idx].status != CPS_BUSY) {
      return idx;
    }
  }
  return -1;
}
int ConnectionPool::async_find_free_socket(int* idx, void* sync_inject) {
  _pipe.async_read_some(boost::asio::buffer(idx, sizeof(int)),
            [=](error_code ec, size_t transferred) {
                if (ec) {
                  dout(0) << "async_pipe read error message:"<< ec.message() << dendl;
                  ((SyncPoint *)sync_inject)->put(-1);
                } else {
                  ((SyncPoint *)sync_inject)->put(0);
                }
            });
  return 0;
}
int ConnectionPool::_check_connection(int idx) {
  if (!_sock_arr[idx].stream) {
    dout(0) << __func__<< "(): ERROR stream is nullptr:" << idx << dendl;
    return -EIO;
  }
  _sock_arr[idx].stream->lowest_layer().non_blocking(true);
  char c = ' ';
  int ret = 0;
  boost::system::error_code ec;
  std::size_t len = _sock_arr[idx].stream->next_layer().receive(boost::asio::mutable_buffer(&c, 1), tcp::socket::message_peek, ec);
  if (len > 0) {
    dout(0) << "ERROR: check_connection to proxy, some data pending, error accur! stream idx:"<< idx << dendl;
    ret = -EBADFD;
  } else if (0 == len) {
    if (ec == boost::asio::error::try_again) {
      ret = 0;
    } else {
      dout(5) << "WARNING: check_connection to proxy, read error:"<< ec.message()
              << " on stream idx:" << idx << dendl;
      ret = -ec.value();
    }
  }
  _sock_arr[idx].stream->lowest_layer().non_blocking(false);
  return ret;
}

int ConnectionPool::try_connect(int idx) {
  if (idx < 0 || idx >= _total_sock_number) {
    return ERR_ASSERT;
  }
  if (_sock_arr[idx].status != CPS_BUSY) {
    dout(0) << "ERROR: try_connect status is not busy, status:" << _sock_arr[idx].status
            << " idx:" << idx
            << dendl;
    return ERR_ASSERT;
  }
  boost::system::error_code ec;
  try {
    if (!_sock_arr[idx].stream) {
      dout(0) << "ERROR, stream is nullptr. Server went wrong:" << idx << dendl;
      return ERR_ASSERT;
    }
    if (!_sock_arr[idx].stream->lowest_layer().is_open()) {
      _sock_arr[idx].stream->lowest_layer().open(tcp::v4(), ec);
      if (ec) {
        dout(0) << __func__ << " ERROR, reopen socket error:" << ec.message() << dendl;
      }
    } else {
      dout(30) << __func__ << " socket is already open, idx:" << idx  << dendl;
    }
    _sock_arr[idx].stream->lowest_layer().set_option(tcp::no_delay(true));
    _sock_arr[idx].stream->lowest_layer().set_option(boost::asio::socket_base::keep_alive(true));
    boost::asio::io_service io_service;
    boost::asio::ip::tcp::resolver resolver(io_service);
    boost::asio::ip::tcp::resolver::query query(_host, std::to_string(_port));
    boost::asio::ip::tcp::resolver::iterator iter = resolver.resolve(query);
    boost::asio::ip::tcp::endpoint endpoint = iter->endpoint();
    _sock_arr[idx].stream->lowest_layer().connect(endpoint);
  } catch (std::exception const& e) {
    dout(0) << "ERROR: connect to proxy error:"<< e.what()
            << " errno:" << errno
            << dendl;
    return -errno;
  }
  return 0;
}

int ConnectionPool::_fetch_socket(int& old_status, void* sync_inject) {
  int idx = -1;
  if (_use_asio) {
    async_find_free_socket(&idx, sync_inject);
    if (((SyncPoint *)sync_inject)->get() != 0) {
      dout(0) << "ERROR: read from async_pipe error" << dendl;
      return -1;
    }
  } else {
    pthread_mutex_lock(&_mutex);
    while (_free_sock_count <= 0) {
      pthread_cond_wait(&_condition, &_mutex);
    }
    idx = find_free_socket();
  }
  if (idx < 0) {
    dout(0) << "ERROR: cannot find free stream" << dendl;
    return -1;
  }
  dout(30) << __func__ << "() find free socket:" << idx
           << " status:" << _sock_arr[idx].status
           << dendl;

  old_status = _sock_arr[idx].status;
  _sock_arr[idx].status = CPS_BUSY;
  if (!_use_asio) {
    _free_sock_count--;
    pthread_mutex_unlock(&_mutex);
  }
  if (old_status == CPS_READY) {
    // every time, check this stream connection. Once this stream has problem, close it
    if (_check_connection(idx) != 0) {
      dout(20) << __func__<< "(): stream check_connection error, close it:" << idx << dendl;
      if (_sock_arr[idx].stream->lowest_layer().is_open()) {
        boost::system::error_code ec;
        _sock_arr[idx].stream->lowest_layer().shutdown(tcp::socket::shutdown_both, ec);
        if (ec && ec != boost::system::errc::not_connected) {
          dout(0) << __func__ << "(): ERROR shutdown socket with abcstore_proxy error:"<< ec.message() << dendl;
        }
        _sock_arr[idx].stream->lowest_layer().close(ec);
        if (ec) {
          dout(0) << __func__ << "(): ERROR close socket with abcstore_proxy error:"<< ec.message() << dendl;
        }
      }
      old_status = CPS_INVALID;
    }
  }
  return idx;
}

int ConnectionPool::reopen_socket(int idx) {
  if (_sock_arr[idx].stream->lowest_layer().is_open()) {
    boost::system::error_code ec;
    _sock_arr[idx].stream->lowest_layer().shutdown(tcp::socket::shutdown_both, ec);
    if (ec && ec != boost::system::errc::not_connected) {
      dout(0) << __func__ << "(): ERROR shutdown socket with abcstore_proxy error:"<< ec.message()
              << " idx:" << idx
              << dendl;
    }
    _sock_arr[idx].stream->lowest_layer().close(ec);
    if (ec) {
      dout(0) << __func__ << "(): ERROR close socket with abcstore_proxy error:"<< ec.message()
              << " idx:" << idx
              << dendl;
    }
  } else {
    dout(10) << __func__ << "(): WARNING socket is not open idx:"<< idx << dendl;
  }
  int ret = try_connect(idx);
  if (ret < 0) {
    dout(0) << "ERROR: try reconnect to proxy failed, idx:" << idx
            << " err:" << ret
            << dendl;
    return ret;
  }
  return 0;
}

int ConnectionPool::fetch_socket(std::shared_ptr<boost::asio::ssl::stream<tcp::socket> >& stream, void** asio_ctx) {
  int retry = _conn_retry;
  while (retry >= 0) {
    int old_status = CPS_INVALID;
    int idx;
    dout(30) << __func__  << "(): call _fetch_socket, retry:" << retry << dendl;
    if (asio_ctx) {
      SyncPoint sync_inject(*((boost::asio::io_service *) asio_ctx[0]),
                            *((boost::asio::yield_context *) asio_ctx[1]));
      idx = _fetch_socket(old_status, &sync_inject);
    } else {
      idx = _fetch_socket(old_status);
    }
    if (idx < 0) {
      dout(0) << __func__  << "(): fetch stream with wrong idx:" << idx << dendl;
      return ERR_ASSERT;
    }
    if (old_status == CPS_READY) {
      stream = _sock_arr[idx].stream;
      return idx;
    } else {
      // try make connect or reconnect
      dout(30) << __func__  << "(): stream status is invalid on idx "<< idx
               << " try_connect " << dendl;
      if (try_connect(idx) == 0) {
        stream = _sock_arr[idx].stream;
        return idx;
      } else {
        dout(0) << "ERROR: try reconnect to proxy failed, call free_socket:" << idx << dendl;
        _free_socket(idx, true);
      }
    }
    retry--;
  }
  return ERR_CONN;
}

int ConnectionPool::_free_socket(int idx, bool close)
{
  if (idx < 0 && idx >= _total_sock_number) {
    dout(0) << "ERROR: free stream with wrong idx:" << idx << dendl;
    return ERR_ASSERT;
  }
  int ret = 0;
  if (!_use_asio) {
    pthread_mutex_lock(&_mutex);
  }
  if (_sock_arr[idx].status != CPS_BUSY) {
    dout(0) << __func__ << "(): ERROR stream idx:" << idx << "status is not busy, status:" << _sock_arr[idx].status << dendl;
    ret = ERR_ASSERT;
  } else {
    if (close) {
      // connect error, close stream
      if (_sock_arr[idx].stream) {
        dout(30) << __func__  << "(): close connection idx:" << idx << dendl;
        if (_sock_arr[idx].stream->lowest_layer().is_open()) {
          boost::system::error_code ec;
          _sock_arr[idx].stream->lowest_layer().shutdown(tcp::socket::shutdown_both, ec);
          if (ec && ec != boost::system::errc::not_connected) {
            dout(0) << "ERROR: shutdown stream with abcstore_proxy error:"<< ec.message() << dendl;
          }
          _sock_arr[idx].stream->lowest_layer().close(ec);
          if (ec) {
            dout(0) << "ERROR: close stream with abcstore_proxy error:"<< ec.message() << dendl;
          }
        }
        // do not set stream to nullptr, always use it. Only close or reopen!
      } else {
        dout(0) << "ERROR: stream is nullptr:"<< idx << dendl;
      }
      _sock_arr[idx].status = CPS_INVALID;
    } else {
      _sock_arr[idx].status = CPS_READY;
    }
  }
  dout(30) << __func__  << "(): free socket idx:" << idx << dendl;
  if (_use_asio) {
    _pipe.async_write_some(boost::asio::mutable_buffer(&idx, sizeof(int)),
            [=](error_code ec, size_t transferred) {
                if (ec || transferred != sizeof(int)) {
                  dout(0) << "ERROR async_pipe write "<< transferred
                          <<" bytes, error message:"<< ec.message() << dendl;
                }
            });
  } else {
    _free_sock_count++;
    pthread_cond_signal(&_condition);
    pthread_mutex_unlock(&_mutex);
  }
  return ret;
}

int ConnectionPool::free_socket(int idx) {
  if (idx < 0 || idx >= _total_sock_number) {
    dout(0) << "ERROR: free stream with wrong idx:" << idx << dendl;
    return ERR_ASSERT;
  }
  return _free_socket(idx, false);
}

int verify_object_lock(CephContext* cct,
                       map<string, bufferlist>& attrs,
                       bool bypass_perm,
                       bool bypass_governance_mode,
                       const ceph::real_time& mtime) {
  auto aiter = attrs.find(RGW_ATTR_OBJECT_RETENTION);
  if (aiter != attrs.end()) {
    RGWObjectRetention obj_retention;
    try {
      decode(obj_retention, aiter->second);
    } catch (buffer::error& err) {
      ldout(cct, 0) << "ERROR: failed to decode RGWObjectRetention" << dendl;
      return -EIO;
    }
    if (ceph::real_clock::to_time_t(obj_retention.get_retain_until_date()) > ceph_clock_now()) {
      if (obj_retention.get_mode().compare("GOVERNANCE") != 0 || !bypass_perm || !bypass_governance_mode) {
        // if GOVERNANCE MODE work, allow it
        // if not while debug_interval work, allow it
        if (cct->_conf->rgw_worm_debug_interval > 0) {
          if (!satisfy_worm_debug_time(cct, mtime, obj_retention.get_retain_until_date())) {
            return -EACCES;
          }
        } else {
          return -EACCES;
        }
      }
    }
  }
  aiter = attrs.find(RGW_ATTR_OBJECT_LEGAL_HOLD);
  if (aiter != attrs.end()) {
    RGWObjectLegalHold obj_legal_hold;
    try {
      decode(obj_legal_hold, aiter->second);
    } catch (buffer::error& err) {
      ldout(cct, 0) << "ERROR: failed to decode RGWObjectLegalHold" << dendl;
      return -EIO;
    }
    if (obj_legal_hold.is_enabled()) {
      return -EACCES;
    }
  }
  return 0;
}
