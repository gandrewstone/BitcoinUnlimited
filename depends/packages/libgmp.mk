package=libgmp
$(package)_version=6.2.1
$(package)_download_path=https://www.bitcoinunlimited.info/depends-sources
# original source: https://gmplib.org/download/gmp
# $(package)_file_name=$(package)-$($(package)_version).tar.lz
$(package)_file_name=gmp-$($(package)_version).tar.gz
$(package)_sha256_hash=0e19db71bcd2082b404350ce2bd5c32ad54525c10ce28a71cb46d88113fe626b

ifeq  ($(HOST),i686-pc-linux-gnu)
  XTRA_CFG:=--disable-assembly
  $(package)_cflags+=-m32
endif

ifeq  ($(HOST),x86_64-apple-darwin11)
  XTRA_CFG:=--disable-assembly
  XTRA_CFG_ENV:=CC="$(darwin_CC)" CXX="$(darwin_CXX)"
  define $(package)_set_vars
  $(package)_build_opts+=CFLAGS="$($(package)_cflags) $($(package)_cppflags) -fPIC -keep_private_externs"
  endef
else
define $(package)_set_vars
$(package)_build_opts+=CFLAGS="$($(package)_cflags) $($(package)_cppflags) -fPIC"
endef

endif

define $(package)_config_cmds
  $(XTRA_CFG_ENV) ./configure --enable-static --prefix=$($(package)_staging_dir)/$(host_prefix) --host=$(HOST) $(XTRA_CFG)
endef

define $(package)_build_cmds
  $(MAKE) HOST=$(HOST) $($(package)_build_opts)
endef

define $(package)_stage_cmds
  $(MAKE) install
endef

