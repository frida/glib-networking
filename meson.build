project(
  'glib-networking', 'c',
  version: '2.74.0',
  license: 'LGPL2.1+',
  meson_version: '>= 0.60.0',
  default_options: ['c_std=gnu99']
)

prefix = get_option('prefix')
datadir = join_paths(prefix, get_option('datadir'))
libdir = join_paths(prefix, get_option('libdir'))
libexecdir = join_paths(prefix, get_option('libexecdir'))
localedir = join_paths(prefix, get_option('localedir'))

installed_tests_metadir = join_paths(datadir, 'installed-tests', meson.project_name())
installed_tests_execdir = join_paths(libexecdir, 'installed-tests', meson.project_name())

cc = meson.get_compiler('c')
host_system = host_machine.system()

config_h = configuration_data()

config_h.set_quoted('GETTEXT_PACKAGE', meson.project_name())
config_h.set10('ENABLE_DEBUG_LOGS', get_option('debug_logs'))

# compiler flags
common_flags = [
  '-DHAVE_CONFIG_H',
  '-DG_LOG_DOMAIN="GLib-Net"',
  '-DG_LOG_USE_STRUCTURED',
  '-DLOCALE_DIR="@0@"'.format(localedir),
  '-DG_DISABLE_DEPRECATED',
  '-DGLIB_VERSION_MIN_REQUIRED=GLIB_VERSION_2_70'
]

# old versions of glibc require this for resolv.h, which gets included by gio/gnetworking.h
if host_system == 'linux'
  common_flags += '-D_GNU_SOURCE'
endif

# ...and same story for QNX
if host_system == 'qnx'
  common_flags += '-D_QNX_SOURCE'
endif

ndebug = get_option('b_ndebug')
if ndebug == 'true' or (ndebug == 'if-release' and not get_option('debug'))
  common_flags += [
    '-DG_DISABLE_CAST_CHECKS',
    '-DG_DISABLE_ASSERT',
    '-DG_DISABLE_CHECKS'
  ]
endif

build_static = get_option('static_modules') or get_option('default_library') != 'shared'
build_shared = get_option('default_library') != 'static'
if build_static and build_shared and (host_system == 'windows' or host_system == 'cygwin')
  error('On Windows default_library must be "shared" or "static" but not "both"')
endif
if build_static and not build_shared
  common_flags += '-DGLIB_NETWORKING_STATIC_COMPILATION'
endif

add_project_arguments(common_flags, language: 'c')

cflags = cc.get_supported_arguments(['-Werror=declaration-after-statement',
                                     '-Werror=implicit-function-declaration'])
add_project_arguments(cflags, language: 'c')

symbol_map = join_paths(meson.current_source_dir(), meson.project_name() + '.map')

module_ldflags = []

if host_system.contains('linux') or host_system == 'android'
  test_ldflag = '-Wl,--version-script,' + symbol_map
  module_ldflags += cc.get_supported_link_arguments(test_ldflag)
endif

# *** Check GLib GIO        ***
glib_dep = dependency('glib-2.0', version: '>= 2.73.3',
  fallback: ['glib', 'libglib_dep'])
gio_dep = dependency('gio-2.0',
  fallback: ['glib', 'libgio_dep'])
gobject_dep = dependency('gobject-2.0',
  fallback: ['glib', 'libgobject_dep'])
gmodule_dep = dependency('gmodule-2.0',
  fallback: ['glib', 'libgmodule_dep'])

if glib_dep.type_name() == 'internal'
  glib_proj = subproject('glib')
  gio_module_dir = glib_proj.get_variable('glib_giomodulesdir')
else
  gio_module_dir = gio_dep.get_variable('giomoduledir',
                                         pkgconfig_define: ['libdir', join_paths(prefix, libdir)])
endif

assert(gio_module_dir != '', 'GIO_MODULE_DIR is missing from gio-2.0.pc')

# *** Checks for LibProxy   ***
libproxy_dep = dependency('libproxy-1.0', version: '>= 0.4.16', required: get_option('libproxy'))

# *** Checks for GNOME      ***
gsettings_desktop_schemas_dep = dependency('gsettings-desktop-schemas', required: get_option('gnome_proxy'))

backends = []

# *** Check for dl          ***
have_rtld_noload = cc.has_header_symbol('dlfcn.h', 'RTLD_NOLOAD')
config_h.set('HAVE_RTLD_NOLOAD', have_rtld_noload)

# *** Checks for GnuTLS     ***
gnutls_dep = dependency('gnutls', version: '>= 3.7.4', required: get_option('gnutls'))

if gnutls_dep.found()
  backends += ['gnutls']
endif

# *** Checks for OpenSSL    ***
openssl_option = get_option('openssl')
if openssl_option.disabled()
  openssl_dep = []
else
  # We want to use CMake to help us find OpenSSL on Visual
  # Studio-like builds, and we should check that the libssl.lib
  # (or ssleay32.lib) is indeed there by using
  # modules: [ 'OpenSSL::SSL' ]
  openssl_modules = cc.get_argument_syntax() == 'msvc' ? \
                    [ 'OpenSSL::SSL' ] : []
  openssl_dep = dependency('openssl',
                           version: '>= 1.0.2',
                           modules: openssl_modules,
                           required: openssl_option)
  if openssl_dep.found()
    backends += ['openssl']
  endif
endif

if backends.length() == 0
  error('No TLS backends enabled. Please enable at least one TLS backend')
endif

configure_file(
  output: 'config.h',
  configuration: config_h
)

gnome = import('gnome')
i18n = import('i18n')
pkg = import('pkgconfig')

top_inc = include_directories('.')
tls_inc = include_directories('tls')

enable_installed_tests = get_option('installed_tests')
test_template = files('template.test.in')

module_suffix = []
# Keep the autotools convention for shared module suffix because GModule
# depends on it: https://gitlab.gnome.org/GNOME/glib/issues/520
if ['darwin', 'ios'].contains(host_system)
  module_suffix = 'so'
endif

proxy_test_programs = []

# When glib-networking is a subproject this variable is used by parent project
# to know which modules have been built.
giomodules = []

subdir('po')
subdir('proxy')
subdir('tls')

# Will automatically pick it up from the cross file if defined
gnome.post_install(gio_querymodules: gio_module_dir)

summary({
  'GnuTLS support': giomodules.contains('giognutls'),
  'OpenSSL support': giomodules.contains('gioopenssl'),
  'Environment proxy support': giomodules.contains('gioenvironmentproxy'),
  'libproxy support': giomodules.contains('giolibproxy'),
  'GNOME proxy support': giomodules.contains('giognomeproxy'),
}, bool_yn: true)
