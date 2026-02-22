gtest_dep = dependency('gtest', static: false)
gtest_main_dep = dependency('gtest_main', required: true)

test_sources = files('login_tests/Test1.cpp',
  'login_tests/Test2.cpp',
  'login_tests/Test3.cpp',
  'login_tests/Test4.cpp',
  'login_tests/Test5.cpp',
  'login_tests/Test6.cpp',
  'login_tests/Test7.cpp')

poco_foundation = cpp.find_library('PocoFoundation', required: true)
poco_util = cpp.find_library('PocoUtil', required: true)
poco_json = cpp.find_library('PocoJSON', required: true)
poco_net = cpp.find_library('PocoNet', required: true)
poco_data = cpp.find_library('PocoData', required: false) 
poco_data_postgresql = cpp.find_library('PocoDataPostgreSQL', required: false)

rgt_auth_tests = executable(
  'rgt-auth-tests',
  test_sources,
  dependencies: [gtest_dep, gtest_main_dep, poco_foundation, poco_util, poco_json, poco_net, poco_data, poco_data_postgresql],
  include_directories: include_directories('../src/platform', '.'),
  install: false,
  link_args: [
    '-Wl,-rpath,@executable_path/../lib',
    '-Wl,-rpath,/opt/homebrew/lib',
    '-Wl,-rpath,/usr/local/lib',
  ]
)

test(
  'rgt-auth-integration-tests',
  rgt_auth_tests,
  args: [],
  should_fail: false,
  timeout: 30,
)