# SPDX-License-Identifier: GPL-2.0-or-later
include $(TOPDIR)/rules.mk

PKG_NAME:=rp-pppoe-relay-fastpath
PKG_VERSION:=4.0
PKG_RELEASE:=1
PKG_LICENSE:=GPL-2.0-or-later
PKG_LICENSE_FILES:=doc/LICENSE
PKG_BUILD_PARALLEL:=1

# Source comes from this checkout via scripts/build-openwrt.sh.
# Deliberately no official rp-pppoe PKG_SOURCE_URL or feed recipe.
include $(INCLUDE_DIR)/package.mk

define Package/rp-pppoe-relay-fastpath
  SECTION:=net
  CATEGORY:=Network
  TITLE:=RP-PPPoE relay with optional TC/eBPF fastpath
  URL:=https://github.com/lilu0826/rp-pppoe-relay
  DEPENDS:=+libbpf
  CONFLICTS:=rp-pppoe-relay
  PROVIDES:=rp-pppoe-relay
endef

define Package/rp-pppoe-relay-fastpath/description
  RP-PPPoE 4.0 control plane with optional TCX ingress session forwarding.
  Requires Linux 6.6+ and BPF privileges for fastpath; otherwise uses userspace.
endef

CONFIGURE_PATH:=src
CONFIGURE_ARGS += --disable-plugin ac_cv_path_PPPD=/usr/sbin/pppd
MAKE_PATH:=src

define Build/Prepare
	$(INSTALL_DIR) $(PKG_BUILD_DIR)
	$(CP) ./source/. $(PKG_BUILD_DIR)/
endef

define Build/Compile
	+$(MAKE_VARS) $(MAKE) $(PKG_JOBS) -C $(PKG_BUILD_DIR)/src \
		$(TARGET_CONFIGURE_OPTS) FASTPATH=1 \
		PKG_CONFIG="$(STAGING_DIR_HOST)/bin/pkg-config" pppoe-relay
endef

define Package/rp-pppoe-relay-fastpath/conffiles
/etc/default/pppoe-relay-fastpath
endef

define Package/rp-pppoe-relay-fastpath/install
	$(INSTALL_DIR) $(1)/usr/sbin $(1)/etc/init.d $(1)/etc/default
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/src/pppoe-relay $(1)/usr/sbin/
	$(INSTALL_BIN) ./files/pppoe-relay-fastpath.init $(1)/etc/init.d/pppoe-relay-fastpath
	$(INSTALL_CONF) ./files/pppoe-relay-fastpath.default $(1)/etc/default/pppoe-relay-fastpath
endef

$(eval $(call BuildPackage,rp-pppoe-relay-fastpath))
