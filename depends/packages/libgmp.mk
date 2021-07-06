package=libgmp
$(package)_version=6.2.1
$(package)_download_path=https://gmplib.org/download/gmp
# $(package)_file_name=$(package)-$($(package)_version).tar.lz
$(package)_file_name=gmp-$($(package)_version).tar.lz
$(package)_sha256_hash=2c7f4f0d370801b2849c48c9ef3f59553b5f1d3791d070cffb04599f9fc67b41

ifeq  ($(HOST),i686-pc-linux-gnu)
  XTRA_CFG:=--disable-assembly
endif

ifeq  ($(HOST),x86_64-apple-darwin11)
  XTRA_CFG:=--disable-assembly
  # See https://gmplib.org/list-archives/gmp-bugs/2012-January/002499.html
  XTRA_CFG_ENV:=NM=nm CC=clang CXX=clang++
  $(package)_build_opts+=CC=clang CXX=clang++
  define $(package)_set_vars
  $(package)_build_opts+=CFLAGS="$($(package)_cflags) $($(package)_cppflags) -fPIC -keep_private_externs"
  endef
else
define $(package)_set_vars
#$(package)_build_opts= CC="$($(package)_cc)"
$(package)_build_opts+=CFLAGS="$($(package)_cflags) $($(package)_cppflags) -fPIC"
#$(package)_build_opts+=AR="$($(package)_ar)"
#$(package)_build_opts+=RANLIB="$($(package)_ranlib)"
endef

endif

define $(package)_config_cmds
  $(XTRA_CFG_ENV) ./configure --enable-static --host=$(HOST) $(XTRA_CFG)
endef

define $(package)_build_cmds
  $(MAKE) HOST=$(HOST) $($(package)_build_opts)
endef

define $(package)_stage_cmds
  $(MAKE) DESTDIR=$($(package)_staging_dir) install $($(package)_build_opts)
endef

