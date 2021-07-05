package=libgmp
$(package)_version=6.2.1
$(package)_download_path=https://gmplib.org/download/gmp
# $(package)_file_name=$(package)-$($(package)_version).tar.lz
$(package)_file_name=gmp-$($(package)_version).tar.lz
$(package)_sha256_hash=2c7f4f0d370801b2849c48c9ef3f59553b5f1d3791d070cffb04599f9fc67b41

define $(package)_set_vars
$(package)_build_opts= CC="$($(package)_cc)"
$(package)_build_opts+=CFLAGS="$($(package)_cflags) $($(package)_cppflags) -fPIC"
$(package)_build_opts+=AR="$($(package)_ar)"
$(package)_build_opts+=RANLIB="$($(package)_ranlib)"
endef

define $(package)_config_cmds
  ./configure --enable-cxx --enable-static --host=$(HOST)
endef

define $(package)_build_cmds
  $(MAKE) HOST=$(HOST)
endef

define $(package)_stage_cmds
  $(MAKE) DESTDIR=$($(package)_staging_dir) install $($(package)_build_opts)
endef

