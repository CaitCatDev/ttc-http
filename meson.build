project('lchttp', 'c')

pkg = import('pkgconfig')

conf_data = configuration_data()



VERSION_MAJOR = get_option('version_major')
VERSION_MINOR = get_option('version_minor')
VERSION_VENDOR = get_option('version_vendor')

conf_data.set('VERSION_VENDOR', VERSION_VENDOR)
conf_data.set('VERSION_MAJOR', VERSION_MAJOR)
conf_data.set('VERSION_MIN', VERSION_MINOR)

configure_file(input: 'lchttp.h.in', output: 'lchttp.h', configuration: conf_data)

install_headers(meson.current_build_dir() / 'lchttp.h', install_dir: '/usr/local/include/')

lib = library('lchttp', 'lchttp.c', version : f'@VERSION_MAJOR@.@VERSION_MINOR@', soversion: '0', install: true)


pkg.generate(libraries: lib,
  version: f'@VERSION_MAJOR@.@VERSION_MINOR@',
  name: 'lchttp',
  filebase: 'lchttp',
  description: 'A Simple HTTP request builder in C')
