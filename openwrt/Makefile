# SPDX-License-Identifier: GPL-2.0-or-later
include $(TOPDIR)/rules.mk

PKG_NAME:=pppoe-relay-bpf
PKG_VERSION:=1.0.0
PKG_RELEASE:=1
PKG_LICENSE:=GPL-2.0-or-later
PKG_LICENSE_FILES:=LICENSE
PKG_BUILD_PARALLEL:=1

# Local source and host-generated BPF skeleton: scripts/build-openwrt.sh.
include $(INCLUDE_DIR)/package.mk

define Package/pppoe-relay-bpf
  SECTION:=net
  CATEGORY:=Network
  TITLE:=PPPoE relay using TCX/eBPF
  URL:=https://github.com/lilu0826/pppoe-relay-bpf
  DEPENDS:=+libbpf
endef

define Package/pppoe-relay-bpf/description
  PPPoE discovery, session mapping and forwarding in a single BPF program.
  Requires Linux 6.6+ with TCX support and BPF privileges.
endef

define Build/Prepare
	$(INSTALL_DIR) $(PKG_BUILD_DIR)
	$(CP) ./source/. $(PKG_BUILD_DIR)/
endef

define Build/Configure
endef

define Build/Compile
	+$(MAKE_VARS) $(MAKE) $(PKG_JOBS) -C $(PKG_BUILD_DIR)/src \
		$(TARGET_CONFIGURE_OPTS) BPF_PREBUILT=1 \
		CFLAGS="$(TARGET_CFLAGS)" LDFLAGS="$(TARGET_LDFLAGS)" \
		PKG_CONFIG="$(STAGING_DIR_HOST)/bin/pkg-config" pppoe-relay-bpf
endef

define Package/pppoe-relay-bpf/conffiles
/etc/default/pppoe-relay-bpf
endef

define Package/pppoe-relay-bpf/install
	$(INSTALL_DIR) $(1)/usr/sbin $(1)/etc/init.d $(1)/etc/default
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/src/pppoe-relay-bpf $(1)/usr/sbin/
	$(INSTALL_BIN) ./files/pppoe-relay-bpf.init $(1)/etc/init.d/pppoe-relay-bpf
	$(INSTALL_CONF) ./files/pppoe-relay-bpf.default $(1)/etc/default/pppoe-relay-bpf
endef

$(eval $(call BuildPackage,pppoe-relay-bpf))
