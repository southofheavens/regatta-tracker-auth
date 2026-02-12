gtest_dep = dependency('gtest', static: false)

test_sources = files('tests.cpp')

rgt_auth_tests = executable(
  'rgt-auth-tests',
  test_sources,
  dependencies: [gtest_dep],
  include_directories: include_directories('../src/platform'),
  install: false,
)

test(
  'rgt-auth-integration-tests',
  rgt_auth_tests,
  args: [],
  should_fail: false,
  timeout: 30,
)