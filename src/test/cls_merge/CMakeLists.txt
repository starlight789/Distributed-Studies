add_executable(ceph_test_cls_merge
  test_cls_merge.cc
  ../../objclass/merge_cls.cc
  )

set_target_properties(ceph_test_cls_merge PROPERTIES COMPILE_FLAGS
  ${UNITTEST_CXX_FLAGS})
target_link_libraries(ceph_test_cls_merge
  global
  ${UNITTEST_LIBS}
  ${EXTRALIBS}
  ${BLKID_LIBRARIES}
  ${CMAKE_DL_LIBS})

install(TARGETS
  ceph_test_cls_merge
  DESTINATION ${CMAKE_INSTALL_BINDIR})
