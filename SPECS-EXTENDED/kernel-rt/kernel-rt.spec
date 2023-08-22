%global security_hardening none
%global sha512hmac bash %{_sourcedir}/sha512hmac-openssl.sh
%global rt_version rt48
%define uname_r %{version}-%{rt_version}-%{release}
%define version_upstream %(echo %{version} | rev | cut -d'.' -f2- | rev)

# find_debuginfo.sh arguments are set by default in rpm's macros.
# The default arguments regenerate the build-id for vmlinux in the 
# debuginfo package causing a mismatch with the build-id for vmlinuz in
# the kernel package. Therefore, explicilty set the relevant default 
# settings to prevent this behavior.
%undefine _unique_build_ids
%undefine _unique_debug_names
%global _missing_build_ids_terminate_build 1
%global _no_recompute_build_ids 1

%ifarch x86_64
%define arch x86_64
%define archdir x86
%define config_source %{SOURCE1}
%endif

Summary:        Realtime Linux Kernel
Name:           kernel-rt
Version:        5.15.55.1
Release:        3%{?dist}
License:        GPLv2
Vendor:         Microsoft Corporation
Distribution:   Mariner
Group:          System Environment/Kernel
URL:            https://github.com/microsoft/CBL-Mariner-Linux-Kernel
Source0:        https://github.com/microsoft/CBL-Mariner-Linux-Kernel/archive/rolling-lts/mariner-2/%{version}.tar.gz#/kernel-%{version}.tar.gz
Source1:        config
Source2:        sha512hmac-openssl.sh
Source3:        cbl-mariner-ca-20211013.pem
# When updating, make sure to grab the matching patch from 
# https://mirrors.edge.kernel.org/pub/linux/kernel/projects/rt/
# Also, remember to bump the global rt_version macro above ^
Patch0:         patch-%{version_upstream}-%{rt_version}.patch
Patch1:         realtime-with-memcg.patch
Patch2		0001-ice-Add-DSCP-support.patch
Patch3		0002-ice-Add-feature-bitmap-helpers-and-a-check-for-DSCP.patch
Patch4		0003-ice-Fix-link-mode-handling.patch
Patch5		0004-ice-refactor-devlink-getter-fallback-functions-to-vo.patch
Patch6		0005-ice-Fix-macro-name-for-IPv4-fragment-flag.patch
Patch7		0006-ice-Prefer-kcalloc-over-open-coded-arithmetic.patch
Patch8		0007-ice-support-basic-E-Switch-mode-control.patch
Patch9		0008-ice-introduce-VF-port-representor.patch
Patch10		0009-ice-allow-process-VF-opcodes-in-different-ways.patch
Patch11		0010-ice-manage-VSI-antispoof-and-destination-override.patch
Patch12		0011-ice-allow-changing-lan_en-and-lb_en-on-dflt-rules.patch
Patch13		0012-ice-set-and-release-switchdev-environment.patch
Patch14		0013-ice-introduce-new-type-of-VSI-for-switchdev.patch
Patch15		0014-ice-enable-disable-switchdev-when-managing-VFs.patch
Patch16		0015-ice-rebuild-switchdev-when-resetting-all-VFs.patch
Patch17		0016-ice-switchdev-slow-path.patch
Patch18		0017-ice-add-port-representor-ethtool-ops-and-stats.patch
Patch19		0018-ice-implement-low-level-recipes-functions.patch
Patch20		0019-ice-manage-profiles-and-field-vectors.patch
Patch21		0020-ice-create-advanced-switch-recipe.patch
Patch22		0021-ice-allow-adding-advanced-rules.patch
Patch23		0022-ice-allow-deleting-advanced-rules.patch
Patch24		0023-ice-cleanup-rules-info.patch
Patch25		0024-ice-Allow-changing-lan_en-and-lb_en-on-all-kinds-of-.patch
Patch26		0025-ice-ndo_setup_tc-implementation-for-PF.patch
Patch27		0026-ice-ndo_setup_tc-implementation-for-PR.patch
Patch28		0027-ice-Refactor-ice_aqc_link_topo_addr.patch
Patch29		0028-ice-Implement-functions-for-reading-and-setting-GPIO.patch
Patch30		0029-ice-Add-support-for-SMA-control-multiplexer.patch
Patch31		0030-ice-Implement-support-for-SMA-and-U.FL-on-E810-T.patch
Patch32		0031-ice-remove-ring_active-from-ice_ring.patch
Patch33		0032-ice-split-ice_ring-onto-Tx-Rx-separate-structs.patch
Patch34		0033-ice-unify-xdp_rings-accesses.patch
Patch35		0034-ice-do-not-create-xdp_frame-on-XDP_TX.patch
Patch36		0035-ice-propagate-xdp_ring-onto-rx_ring.patch
Patch37		0036-ice-optimize-XDP_TX-workloads.patch
Patch38		0037-ice-introduce-XDP_TX-fallback-path.patch
Patch39		0038-ice-make-use-of-ice_for_each_-macros.patch
Patch40		0039-ice-Add-support-for-VF-rate-limiting.patch
Patch41		0040-ice-update-dim-usage-and-moderation.patch
Patch42		0041-ice-fix-rate-limit-update-after-coalesce-change.patch
Patch43		0042-ice-fix-software-generating-extra-interrupts.patch
Patch44		0043-ice-Forbid-trusted-VFs-in-switchdev-mode.patch
Patch45		0044-ice-Manage-act-flags-for-switchdev-offloads.patch
Patch46		0045-ice-Refactor-PR-ethtool-ops.patch
Patch47		0046-ice-Make-use-of-the-helper-function-devm_add_action_.patch
Patch48		0047-ice-use-devm_kcalloc-instead-of-devm_kzalloc.patch
Patch49		0048-ice-fix-an-error-code-in-ice_ena_vfs.patch
Patch50		0049-ice-Add-infrastructure-for-mqprio-support-via-ndo_se.patch
Patch51		0050-ice-enable-ndo_setup_tc-support-for-mqprio_qdisc.patch
Patch52		0051-ice-Add-tc-flower-filter-support-for-channel.patch
Patch53		0052-ice-support-for-indirect-notification.patch
Patch54		0053-ice-VXLAN-and-Geneve-TC-support.patch
Patch55		0054-ice-low-level-support-for-tunnels.patch
Patch56		0055-ice-support-for-GRE-in-eswitch.patch
Patch57		0056-ice-send-correct-vc-status-in-switchdev.patch
Patch58		0057-ice-Add-support-for-changing-MTU-on-PR-in-switchdev-.patch
Patch59		0058-ice-Add-support-to-print-error-on-PHY-FW-load-failur.patch
Patch60		0059-ice-Fix-clang-Wimplicit-fallthrough-in-ice_pull_qvec.patch
Patch61		0060-ice-fix-error-return-code-in-ice_get_recp_frm_fw.patch
Patch62		0061-ice-Remove-boolean-vlan_promisc-flag-from-function.patch
Patch63		0062-ice-Clear-synchronized-addrs-when-adding-VFs-in-swit.patch
Patch64		0063-ice-Hide-bus-info-in-ethtool-for-PRs-in-switchdev-mo.patch
Patch65		0064-ice-Remove-toggling-of-antispoof-for-VF-trusted-prom.patch
Patch66		0065-ice-rearm-other-interrupt-cause-register-after-enabl.patch
Patch67		0066-ice-Fix-problems-with-DSCP-QoS-implementation.patch
Patch68		0067-ice-ignore-dropped-packets-during-init.patch
Patch69		0068-ice-fix-choosing-UDP-header-type.patch
Patch70		0069-ice-fix-adding-different-tunnels.patch
Patch71		0070-ice-safer-stats-processing.patch
Patch72		0071-devlink-Add-enable_iwarp-generic-device-param.patch
Patch73		0072-net-ice-Add-support-for-enable_iwarp-and-enable_roce.patch
Patch74		0073-net-ice-Fix-boolean-assignment.patch
Patch75		0074-ice-Add-package-PTYPE-enable-information.patch
Patch76		0075-ice-refactor-PTYPE-validating.patch
Patch77		0076-ice-Refactor-promiscuous-functions.patch
Patch78		0077-ice-Refactor-status-flow-for-DDP-load.patch
Patch79		0078-ice-Remove-string-printing-for-ice_status.patch
Patch80		0079-ice-Use-int-for-ice_status.patch
Patch81		0080-ice-Remove-enum-ice_status.patch
Patch82		0081-ice-Cleanup-after-ice_status-removal.patch
Patch83		0082-ice-Remove-excess-error-variables.patch
Patch84		0083-ice-Propagate-error-codes.patch
Patch85		0084-ice-Remove-unnecessary-casts.patch
Patch86		0085-ice-Remove-unused-ICE_FLOW_SEG_HDRS_L2_MASK.patch
Patch87		0086-ice-devlink-add-shadow-ram-region-to-snapshot-Shadow.patch
Patch88		0087-ice-move-and-rename-ice_check_for_pending_update.patch
Patch89		0088-ice-move-ice_devlink_flash_update-and-merge-with-ice.patch
Patch90		0089-ice-reduce-time-to-read-Option-ROM-CIVD-data.patch
Patch91		0090-ice-update-to-newer-kernel-API.patch
Patch92		0091-ice-use-prefetch-methods.patch
Patch93		0092-ice-tighter-control-over-VSI_DOWN-state.patch
Patch94		0093-ice-use-modern-kernel-API-for-kick.patch
Patch95		0094-ice-Fix-E810-PTP-reset-flow.patch
Patch96		0095-ice-introduce-ice_base_incval-function.patch
Patch97		0096-ice-PTP-move-setting-of-tstamp_config.patch
Patch98		0097-ice-use-int-err-instead-of-int-status-in-ice_ptp_hw..patch
Patch99		0098-ice-introduce-ice_ptp_init_phc-function.patch
Patch100	0099-ice-convert-clk_freq-capability-into-time_ref.patch
Patch101	0100-ice-implement-basic-E822-PTP-support.patch
Patch102	0101-ice-ensure-the-hardware-Clock-Generation-Unit-is-con.patch
Patch103	0102-ice-exit-bypass-mode-once-hardware-finishes-timestam.patch
Patch104	0103-ice-support-crosstimestamping-on-E822-devices-if-sup.patch
Patch105	0104-ice-trivial-fix-odd-indenting.patch
Patch106	0105-ice-switch-to-napi_build_skb.patch
Patch107	0106-ice-Add-flow-director-support-for-channel-mode.patch
Patch108	0107-ice-replay-advanced-rules-after-reset.patch
Patch109	0108-ice-improve-switchdev-s-slow-path.patch
Patch110	0109-ice-Slightly-simply-ice_find_free_recp_res_idx.patch
Patch111	0110-ice-Optimize-a-few-bitmap-operations.patch
Patch112	0111-ice-Use-bitmap_free-to-free-bitmap.patch
Patch113	0112-ice-Avoid-RTNL-lock-when-re-creating-auxiliary-devic.patch
Patch114	0113-ice-Match-on-all-profiles-in-slow-path.patch
Patch115	0114-ice-fix-setting-l4-port-flag-when-adding-filter.patch
Patch116	0115-ice-fix-NULL-pointer-dereference-in-ice_update_vsi_t.patch
Patch117	0116-ice-destroy-flow-director-filter-mutex-after-releasi.patch
Patch118	0117-ice-Remove-useless-DMA-32-fallback-configuration.patch
Patch119	0118-ice-respect-metadata-in-legacy-rx-ice_construct_skb.patch
Patch120	0119-ice-don-t-reserve-excessive-XDP_PACKET_HEADROOM-on-X.patch
Patch121	0120-ice-respect-metadata-on-XSK-Rx-to-skb.patch
Patch122	0121-ice-add-support-for-DSCP-QoS-for-IDC.patch
Patch123	0122-ice-Remove-likely-for-napi_complete_done.patch
Patch124	0123-ice-xsk-Force-rings-to-be-sized-to-power-of-2.patch
Patch125	0124-ice-Refactor-spoofcheck-configuration-functions.patch
Patch126	0125-ice-Add-helper-function-for-adding-VLAN-0.patch
Patch127	0126-ice-Add-new-VSI-VLAN-ops.patch
Patch128	0127-ice-Introduce-ice_vlan-struct.patch
Patch129	0128-ice-Refactor-vf-port_vlan_info-to-use-ice_vlan.patch
Patch130	0129-ice-Use-the-proto-argument-for-VLAN-ops.patch
Patch131	0130-ice-Adjust-naming-for-inner-VLAN-operations.patch
Patch132	0131-ice-Add-outer_vlan_ops-and-VSI-specific-VLAN-ops-imp.patch
Patch133	0132-ice-Add-hot-path-support-for-802.1Q-and-802.1ad-VLAN.patch
Patch134	0133-virtchnl-Use-the-BIT-macro-for-capability-offload-fl.patch
Patch135	0134-virtchnl-Add-support-for-new-VLAN-capabilities.patch
Patch136	0135-ice-Add-support-for-VIRTCHNL_VF_OFFLOAD_VLAN_V2.patch
Patch137	0136-ice-Support-configuring-the-device-to-Double-VLAN-Mo.patch
Patch138	0137-ice-Advertise-802.1ad-VLAN-filtering-and-offloads-fo.patch
Patch139	0138-ice-Add-support-for-802.1ad-port-VLANs-VF.patch
Patch140	0139-ice-Add-ability-for-PF-admin-to-enable-VF-VLAN-pruni.patch
Patch141	0140-ice-Simplify-tracking-status-of-RDMA-support.patch
Patch142	0141-ice-add-TTY-for-GNSS-module-for-E810T-device.patch
Patch143	0142-ice-refactor-unwind-cleanup-in-eswitch-mode.patch
Patch144	0143-ice-store-VF-pointer-instead-of-VF-ID.patch
Patch145	0144-ice-pass-num_vfs-to-ice_set_per_vf_res.patch
Patch146	0145-ice-move-clear_malvf-call-in-ice_free_vfs.patch
Patch147	0146-ice-move-VFLR-acknowledge-during-ice_free_vfs.patch
Patch148	0147-ice-remove-checks-in-ice_vc_send_msg_to_vf.patch
Patch149	0148-ice-use-ice_for_each_vf-for-iteration-during-removal.patch
Patch150	0149-ice-convert-ice_for_each_vf-to-include-VF-entry-iter.patch
Patch151	0150-ice-factor-VF-variables-to-separate-structure.patch
Patch152	0151-ice-introduce-VF-accessor-functions.patch
Patch153	0152-ice-convert-VF-storage-to-hash-table-with-krefs-and-.patch
Patch154	0153-ice-Add-support-for-inner-etype-in-switchdev.patch
Patch155	0154-ice-change-can-t-set-link-message-to-dbg-level.patch
Patch156	0155-ice-avoid-XDP-checks-in-ice_clean_tx_irq.patch
Patch157	0156-ice-Add-support-for-outer-dest-MAC-for-ADQ-tunnels.patch
Patch158	0157-ice-Fix-FV-offset-searching.patch
Patch159	0158-ice-rename-ice_sriov.c-to-ice_vf_mbx.c.patch
Patch160	0159-ice-rename-ice_virtchnl_pf.c-to-ice_sriov.c.patch
Patch161	0160-ice-remove-circular-header-dependencies-on-ice.h.patch
Patch162	0161-ice-convert-vf-vc_ops-to-a-const-pointer.patch
Patch163	0162-ice-remove-unused-definitions-from-ice_sriov.h.patch
Patch164	0163-ice-rename-ICE_MAX_VF_COUNT-to-avoid-confusion.patch
Patch165	0164-ice-refactor-spoofchk-control-code-in-ice_sriov.c.patch
Patch166	0165-ice-move-ice_set_vf_port_vlan-near-other-.ndo-ops.patch
Patch167	0166-ice-cleanup-error-logging-for-ice_ena_vfs.patch
Patch168	0167-ice-log-an-error-message-when-eswitch-fails-to-confi.patch
Patch169	0168-ice-use-ice_is_vf_trusted-helper-function.patch
Patch170	0169-ice-introduce-ice_vf_lib.c-ice_vf_lib.h-and-ice_vf_l.patch
Patch171	0170-ice-fix-incorrect-dev_dbg-print-mistaking-i-for-vf-v.patch
Patch172	0171-ice-introduce-VF-operations-structure-for-reset-flow.patch
Patch173	0172-ice-fix-a-long-line-warning-in-ice_reset_vf.patch
Patch174	0173-ice-move-reset-functionality-into-ice_vf_lib.c.patch
Patch175	0174-ice-drop-is_vflr-parameter-from-ice_reset_all_vfs.patch
Patch176	0175-ice-make-ice_reset_all_vfs-void.patch
Patch177	0176-ice-convert-ice_reset_vf-to-standard-error-codes.patch
Patch178	0177-ice-convert-ice_reset_vf-to-take-flags.patch
Patch179	0178-ice-introduce-ICE_VF_RESET_NOTIFY-flag.patch
Patch180	0179-ice-introduce-ICE_VF_RESET_LOCK-flag.patch
Patch181	0180-ice-cleanup-long-lines-in-ice_sriov.c.patch
Patch182	0181-ice-introduce-ice_virtchnl.c-and-ice_virtchnl.h.patch
Patch183	0182-ice-Add-slow-path-offload-stats-on-port-representor-.patch
Patch184	0183-ice-remove-PF-pointer-from-ice_check_vf_init.patch
Patch185	0184-ice-fix-return-value-check-in-ice_gnss.c.patch
Patch186	0185-ice-add-trace-events-for-tx-timestamps.patch
Patch187	0186-ice-Fix-MAC-address-setting.patch
Patch188	0187-ice-Fix-broken-IFF_ALLMULTI-handling.patch
Patch189	0188-ice-Set-txq_teid-to-ICE_INVAL_TEID-on-ring-creation.patch
Patch190	0189-ice-Do-not-skip-not-enabled-queues-in-ice_vc_dis_qs_.patch
Patch191	0190-ice-clear-cmd_type_offset_bsz-for-TX-rings.patch
Patch192	0191-ice-arfs-fix-use-after-free-when-freeing-rx_cpu_rmap.patch
Patch193	0192-ice-allow-creating-VFs-for-CONFIG_NET_SWITCHDEV.patch
Patch194	0193-ice-fix-crash-in-switchdev-mode.patch
Patch195	0194-ice-Fix-memory-leak-in-ice_get_orom_civd_data.patch
Patch196	0195-ice-Fix-incorrect-locking-in-ice_vc_process_vf_msg.patch
Patch197	0196-ice-Protect-vf_state-check-by-cfg_lock-in-ice_vc_pro.patch
Patch198	0197-ice-fix-use-after-free-when-deinitializing-mailbox-s.patch
Patch199	0198-ice-clear-stale-Tx-queue-settings-before-configuring.patch
Patch200	0199-iavf-Add-change-MTU-message.patch
Patch201	0200-iavf-Log-info-when-VF-is-entering-and-leaving-Allmul.patch
Patch202	0201-iavf-Enable-setting-RSS-hash-key.patch
Patch203	0202-iavf-Refactor-iavf_mac_filter-struct-memory-usage.patch
Patch204	0203-iavf-Fix-static-code-analysis-warning.patch
Patch205	0204-iavf-Refactor-text-of-informational-message.patch
Patch206	0205-iavf-Refactor-string-format-to-avoid-static-analysis.patch
Patch207	0206-iavf-Fix-displaying-queue-statistics-shown-by-ethtoo.patch
Patch208	0207-iavf-Add-support-for-VIRTCHNL_VF_OFFLOAD_VLAN_V2-neg.patch
Patch209	0208-iavf-Add-support-VIRTCHNL_VF_OFFLOAD_VLAN_V2-during-.patch
Patch210	0209-iavf-Add-support-for-VIRTCHNL_VF_OFFLOAD_VLAN_V2-hot.patch
Patch211	0210-iavf-Add-support-for-VIRTCHNL_VF_OFFLOAD_VLAN_V2-off.patch
Patch212	0211-iavf-Restrict-maximum-VLAN-filters-for-VIRTCHNL_VF_O.patch
Patch213	0212-iavf-switch-to-napi_build_skb.patch
Patch214	0213-iavf-remove-an-unneeded-variable.patch
Patch215	0214-iavf-Fix-adopting-new-combined-setting.patch
Patch216	0215-iavf-Remove-useless-DMA-32-fallback-configuration.patch
Patch217	0216-iavf-Add-support-for-50G-100G-in-AIM-algorithm.patch
Patch218	0217-iavf-refactor-processing-of-VLAN-V2-capability-messa.patch
Patch219	0218-iavf-Add-usage-of-new-virtchnl-format-to-set-default.patch
Patch220	0219-iavf-stop-leaking-iavf_status-as-errno-values.patch
Patch221	0220-iavf-Fix-incorrect-use-of-assigning-iavf_status-to-i.patch
Patch222	0221-iavf-Remove-non-inclusive-language.patch
Patch223	0222-ice-block-LAN-in-case-of-VF-to-VF-offload.patch
Patch224	0223-devlink-Allow-control-devlink-ops-behavior-through-f.patch
Patch225	0224-ice-Open-devlink-when-device-is-ready.patch
Patch226	0225-ice-support-immediate-firmware-activation-via-devlin.patch
Patch227	0226-ice-wait-5-s-for-EMP-reset-after-firmware-flash.patch
# Kernel CVEs are addressed by moving to a newer version of the stable kernel.
# Since kernel CVEs are filed against the upstream kernel version and not the
# stable kernel version, our automated tooling will still flag the CVE as not
# fixed.
# To indicate a kernel CVE is fixed to our automated tooling, add nopatch files
# but do not apply them as a real patch. Each nopatch file should contain
# information on why the CVE nopatch was applied.
BuildRequires:  audit-devel
BuildRequires:  bash
BuildRequires:  bc
BuildRequires:  diffutils
BuildRequires:  dwarves
BuildRequires:  elfutils-libelf-devel
BuildRequires:  glib-devel
BuildRequires:  kbd
BuildRequires:  kmod-devel
BuildRequires:  libdnet-devel
BuildRequires:  libmspack-devel
BuildRequires:  openssl
BuildRequires:  openssl-devel
BuildRequires:  pam-devel
BuildRequires:  procps-ng-devel
BuildRequires:  python3-devel
BuildRequires:  sed
Requires:       filesystem
Requires:       kmod
Requires(post): coreutils
Requires(postun): coreutils
ExclusiveArch:  x86_64
%ifarch x86_64
BuildRequires:  pciutils-devel
%endif
# When updating the config files it is important to sanitize them.
# Steps for updating a config file:
#  1. Extract the linux sources into a folder
#  2. Add the current config file to the folder
#  3. Run `make menuconfig` to edit the file (Manually editing is not recommended)
#  4. Save the config file
#  5. Copy the config file back into the kernel spec folder
#  6. Revert any undesired changes (GCC related changes, etc)
#  8. Build the kernel package
#  9. Apply the changes listed in the log file (if any) to the config file
#  10. Verify the rest of the config file looks ok
# If there are significant changes to the config file, disable the config check and build the
# kernel rpm. The final config file is included in /boot in the rpm.

%description
The kernel package contains the Linux kernel.

%package devel
Summary:        Kernel Dev
Group:          System Environment/Kernel
Requires:       %{name} = %{version}-%{release}
Requires:       gawk
Requires:       python3
Obsoletes:      linux-dev

%description devel
This package contains the Linux kernel dev files

%package drivers-accessibility
Summary:        Kernel accessibility modules
Group:          System Environment/Kernel
Requires:       %{name} = %{version}-%{release}

%description drivers-accessibility
This package contains the Linux kernel accessibility support

%package drivers-sound
Summary:        Kernel Sound modules
Group:          System Environment/Kernel
Requires:       %{name} = %{version}-%{release}

%description drivers-sound
This package contains the Linux kernel sound support

%package docs
Summary:        Kernel docs
Group:          System Environment/Kernel
Requires:       python3

%description docs
This package contains the Linux kernel doc files

%package tools
Summary:        This package contains the 'perf' performance analysis tools for Linux kernel
Group:          System/Tools
Requires:       %{name} = %{version}-%{release}
Requires:       audit

%description tools
This package contains the 'perf' performance analysis tools for Linux kernel.

%package -n     python3-perf
Summary:        Python 3 extension for perf tools
Requires:       python3

%description -n python3-perf
This package contains the Python 3 extension for the 'perf' performance analysis tools for Linux kernel.

%package dtb
Summary:        This package contains common device tree blobs (dtb)
Group:          System Environment/Kernel

%description dtb
This package contains common device tree blobs (dtb)

%package -n     bpftool
Summary:        Inspection and simple manipulation of eBPF programs and maps

%description -n bpftool
This package contains the bpftool, which allows inspection and simple
manipulation of eBPF programs and maps.

%prep
%setup -q -n CBL-Mariner-Linux-Kernel-rolling-lts-mariner-2-%{version}
%patch0 -p1
%patch1 -p1
%patch2	-p1
%patch3	-p1
%patch4	-p1
%patch5	-p1
%patch6	-p1
%patch7	-p1
%patch8	-p1
%patch9	-p1
%patch10 -p1
%patch11 -p1
%patch12 -p1
%patch13 -p1
%patch14 -p1
%patch15 -p1
%patch16 -p1
%patch17 -p1
%patch18 -p1
%patch19 -p1
%patch20 -p1
%patch21 -p1
%patch22 -p1
%patch23 -p1
%patch24 -p1
%patch25 -p1
%patch26 -p1
%patch27 -p1
%patch28 -p1
%patch29 -p1
%patch30 -p1
%patch31 -p1
%patch32 -p1
%patch33 -p1
%patch34 -p1
%patch35 -p1
%patch36 -p1
%patch37 -p1
%patch38 -p1
%patch39 -p1
%patch40 -p1
%patch41 -p1
%patch42 -p1
%patch43 -p1
%patch44 -p1
%patch45 -p1
%patch46 -p1
%patch47 -p1
%patch48 -p1
%patch49 -p1
%patch50 -p1
%patch51 -p1
%patch52 -p1
%patch53 -p1
%patch54 -p1
%patch55 -p1
%patch56 -p1
%patch57 -p1
%patch58 -p1
%patch59 -p1
%patch60 -p1
%patch61 -p1
%patch62 -p1
%patch63 -p1
%patch64 -p1
%patch65 -p1
%patch66 -p1
%patch67 -p1
%patch68 -p1
%patch69 -p1
%patch70 -p1
%patch71 -p1
%patch72 -p1
%patch73 -p1
%patch74 -p1
%patch75 -p1
%patch76 -p1
%patch77 -p1
%patch78 -p1
%patch79 -p1
%patch80 -p1
%patch81 -p1
%patch82 -p1
%patch83 -p1
%patch84 -p1
%patch85 -p1
%patch86 -p1
%patch87 -p1
%patch88 -p1
%patch89 -p1
%patch90 -p1
%patch91 -p1
%patch92 -p1
%patch93 -p1
%patch94 -p1
%patch95 -p1
%patch96 -p1
%patch97 -p1
%patch98 -p1
%patch99 -p1
%patch100 -p1
%patch101 -p1
%patch102 -p1
%patch103 -p1
%patch104 -p1
%patch105 -p1
%patch106 -p1
%patch107 -p1
%patch108 -p1
%patch109 -p1
%patch110 -p1
%patch111 -p1
%patch112 -p1
%patch113 -p1
%patch114 -p1
%patch115 -p1
%patch116 -p1
%patch117 -p1
%patch118 -p1
%patch119 -p1
%patch120 -p1
%patch121 -p1
%patch122 -p1
%patch123 -p1
%patch124 -p1
%patch125 -p1
%patch126 -p1
%patch127 -p1
%patch128 -p1
%patch129 -p1
%patch130 -p1
%patch131 -p1
%patch132 -p1
%patch133 -p1
%patch134 -p1
%patch135 -p1
%patch136 -p1
%patch137 -p1
%patch138 -p1
%patch139 -p1
%patch140 -p1
%patch141 -p1
%patch142 -p1
%patch143 -p1
%patch144 -p1
%patch145 -p1
%patch146 -p1
%patch147 -p1
%patch148 -p1
%patch149 -p1
%patch150 -p1
%patch151 -p1
%patch152 -p1
%patch153 -p1
%patch154 -p1
%patch155 -p1
%patch156 -p1
%patch157 -p1
%patch158 -p1
%patch159 -p1
%patch160 -p1
%patch161 -p1
%patch162 -p1
%patch163 -p1
%patch164 -p1
%patch165 -p1
%patch166 -p1
%patch167 -p1
%patch168 -p1
%patch169 -p1
%patch170 -p1
%patch171 -p1
%patch172 -p1
%patch173 -p1
%patch174 -p1
%patch175 -p1
%patch176 -p1
%patch177 -p1
%patch178 -p1
%patch179 -p1
%patch180 -p1
%patch181 -p1
%patch182 -p1
%patch183 -p1
%patch184 -p1
%patch185 -p1
%patch186 -p1
%patch187 -p1
%patch188 -p1
%patch189 -p1
%patch190 -p1
%patch191 -p1
%patch192 -p1
%patch193 -p1
%patch194 -p1
%patch195 -p1
%patch196 -p1
%patch197 -p1
%patch198 -p1
%patch199 -p1
%patch200 -p1
%patch201 -p1
%patch202 -p1
%patch203 -p1
%patch204 -p1
%patch205 -p1
%patch206 -p1
%patch207 -p1
%patch208 -p1
%patch209 -p1
%patch210 -p1
%patch211 -p1
%patch212 -p1
%patch213 -p1
%patch214 -p1
%patch215 -p1
%patch216 -p1
%patch217 -p1
%patch218 -p1
%patch219 -p1
%patch220 -p1
%patch221 -p1
%patch222 -p1
%patch223 -p1
%patch224 -p1
%patch225 -p1
%patch226 -p1
%patch227 -p1

make mrproper

cp %{config_source} .config

# Add CBL-Mariner cert into kernel's trusted keyring
cp %{SOURCE3} certs/mariner.pem
sed -i 's#CONFIG_SYSTEM_TRUSTED_KEYS=""#CONFIG_SYSTEM_TRUSTED_KEYS="certs/mariner.pem"#' .config

cp .config current_config
sed -i 's/CONFIG_LOCALVERSION=""/CONFIG_LOCALVERSION="-%{release}"/' .config
make LC_ALL=  ARCH=%{arch} oldconfig

# Verify the config files match
cp .config new_config
sed -i 's/CONFIG_LOCALVERSION=".*"/CONFIG_LOCALVERSION=""/' new_config
diff --unified new_config current_config > config_diff || true
if [ -s config_diff ]; then
    printf "\n\n\n\n\n\n\n\n"
    cat config_diff
    printf "\n\n\n\n\n\n\n\n"
    echo "Config file has unexpected changes"
    echo "Update config file to set changed values explicitly"

#  (DISABLE THIS IF INTENTIONALLY UPDATING THE CONFIG FILE)
    exit 1
fi

%build
make VERBOSE=1 KBUILD_BUILD_VERSION="1" KBUILD_BUILD_HOST="CBL-Mariner" ARCH=%{arch} %{?_smp_mflags}

# Compile perf, python3-perf
make -C tools/perf PYTHON=%{python3} all

%ifarch x86_64
make -C tools turbostat cpupower
%endif

#Compile bpftool
make -C tools/bpf/bpftool

%define __modules_install_post \
for MODULE in `find %{buildroot}/lib/modules/%{uname_r} -name *.ko` ; do \
    ./scripts/sign-file sha512 certs/signing_key.pem certs/signing_key.x509 $MODULE \
    rm -f $MODULE.{sig,dig} \
    xz $MODULE \
    done \
%{nil}

# We want to compress modules after stripping. Extra step is added to
# the default __spec_install_post.
%define __spec_install_post\
    %{?__debug_package:%{__debug_install_post}}\
    %{__arch_install_post}\
    %{__os_install_post}\
    %{__modules_install_post}\
%{nil}

%install
install -vdm 755 %{buildroot}%{_sysconfdir}
install -vdm 700 %{buildroot}/boot
install -vdm 755 %{buildroot}%{_defaultdocdir}/linux-%{uname_r}
install -vdm 755 %{buildroot}%{_prefix}/src/linux-headers-%{uname_r}
install -vdm 755 %{buildroot}%{_libdir}/debug/lib/modules/%{uname_r}
make INSTALL_MOD_PATH=%{buildroot} modules_install

%ifarch x86_64
install -vm 600 arch/x86/boot/bzImage %{buildroot}/boot/vmlinuz-%{uname_r}
%endif

# Restrict the permission on System.map-X file
install -vm 400 System.map %{buildroot}/boot/System.map-%{uname_r}
install -vm 600 .config %{buildroot}/boot/config-%{uname_r}
cp -r Documentation/*        %{buildroot}%{_defaultdocdir}/linux-%{uname_r}
install -vm 644 vmlinux %{buildroot}%{_libdir}/debug/lib/modules/%{uname_r}/vmlinux-%{uname_r}
# `perf test vmlinux` needs it
ln -s vmlinux-%{uname_r} %{buildroot}%{_libdir}/debug/lib/modules/%{uname_r}/vmlinux

cat > %{buildroot}/boot/linux-%{uname_r}.cfg << "EOF"
# GRUB Environment Block
mariner_cmdline=init=/lib/systemd/systemd ro loglevel=3 quiet no-vmw-sta crashkernel=256M
mariner_linux=vmlinuz-%{uname_r}
mariner_initrd=initrd.img-%{uname_r}
EOF
chmod 600 %{buildroot}/boot/linux-%{uname_r}.cfg

# hmac sign the kernel for FIPS
%{sha512hmac} %{buildroot}/boot/vmlinuz-%{uname_r} | sed -e "s,$RPM_BUILD_ROOT,," > %{buildroot}/boot/.vmlinuz-%{uname_r}.hmac
cp %{buildroot}/boot/.vmlinuz-%{uname_r}.hmac %{buildroot}/lib/modules/%{uname_r}/.vmlinuz.hmac

# Register myself to initramfs
mkdir -p %{buildroot}/%{_localstatedir}/lib/initramfs/kernel
cat > %{buildroot}/%{_localstatedir}/lib/initramfs/kernel/%{uname_r} << "EOF"
--add-drivers "xen-scsifront xen-blkfront xen-acpi-processor xen-evtchn xen-gntalloc xen-gntdev xen-privcmd xen-pciback xenfs hv_utils hv_vmbus hv_storvsc hv_netvsc hv_sock hv_balloon virtio_blk virtio-rng virtio_console virtio_crypto virtio_mem vmw_vsock_virtio_transport vmw_vsock_virtio_transport_common 9pnet_virtio vrf"
EOF

#    Cleanup dangling symlinks
rm -rf %{buildroot}/lib/modules/%{uname_r}/source
rm -rf %{buildroot}/lib/modules/%{uname_r}/build

find . -name Makefile* -o -name Kconfig* -o -name *.pl | xargs  sh -c 'cp --parents "$@" %{buildroot}%{_prefix}/src/linux-headers-%{uname_r}' copy
find arch/%{archdir}/include include scripts -type f | xargs  sh -c 'cp --parents "$@" %{buildroot}%{_prefix}/src/linux-headers-%{uname_r}' copy
find $(find arch/%{archdir} -name include -o -name scripts -type d) -type f | xargs  sh -c 'cp --parents "$@" %{buildroot}%{_prefix}/src/linux-headers-%{uname_r}' copy
find arch/%{archdir}/include Module.symvers include scripts -type f | xargs  sh -c 'cp --parents "$@" %{buildroot}%{_prefix}/src/linux-headers-%{uname_r}' copy
%ifarch x86_64
# CONFIG_STACK_VALIDATION=y requires objtool to build external modules
install -vsm 755 tools/objtool/objtool %{buildroot}%{_prefix}/src/linux-headers-%{uname_r}/tools/objtool/
install -vsm 755 tools/objtool/fixdep %{buildroot}%{_prefix}/src/linux-headers-%{uname_r}/tools/objtool/
%endif

cp .config %{buildroot}%{_prefix}/src/linux-headers-%{uname_r} # copy .config manually to be where it's expected to be
ln -sf "%{_prefix}/src/linux-headers-%{uname_r}" "%{buildroot}/lib/modules/%{uname_r}/build"
find %{buildroot}/lib/modules -name '*.ko' -print0 | xargs -0 chmod u+x

# disable (JOBS=1) parallel build to fix this issue:
# fixdep: error opening depfile: ./.plugin_cfg80211.o.d: No such file or directory
# Linux version that was affected is 4.4.26
make -C tools JOBS=1 DESTDIR=%{buildroot} prefix=%{_prefix} perf_install

# Install python3-perf
make -C tools/perf DESTDIR=%{buildroot} prefix=%{_prefix} install-python_ext

# Install bpftool
make -C tools/bpf/bpftool DESTDIR=%{buildroot} prefix=%{_prefix} bash_compdir=%{_sysconfdir}/bash_completion.d/ mandir=%{_mandir} install

%ifarch x86_64
# Install turbostat cpupower
make -C tools DESTDIR=%{buildroot} prefix=%{_prefix} bash_compdir=%{_sysconfdir}/bash_completion.d/ mandir=%{_mandir} turbostat_install cpupower_install
%endif

# Remove trace (symlink to perf). This file creates duplicate identical debug symbols
rm -vf %{buildroot}%{_bindir}/trace

%triggerin -- initramfs
mkdir -p %{_localstatedir}/lib/rpm-state/initramfs/pending
touch %{_localstatedir}/lib/rpm-state/initramfs/pending/%{uname_r}
echo "initrd generation of kernel %{uname_r} will be triggered later" >&2

%triggerun -- initramfs
rm -rf %{_localstatedir}/lib/rpm-state/initramfs/pending/%{uname_r}
rm -rf /boot/initrd.img-%{uname_r}
echo "initrd of kernel %{uname_r} removed" >&2

%postun
if [ ! -e /boot/mariner.cfg ]
then
     ls /boot/linux-*.cfg 1> /dev/null 2>&1
     if [ $? -eq 0 ]
     then
          list=`ls -tu /boot/linux-*.cfg | head -n1`
          test -n "$list" && ln -sf "$list" /boot/mariner.cfg
     fi
fi

%post
/sbin/depmod -a %{uname_r}
ln -sf linux-%{uname_r}.cfg /boot/mariner.cfg

%post drivers-accessibility
/sbin/depmod -a %{uname_r}

%post drivers-sound
/sbin/depmod -a %{uname_r}

%files
%defattr(-,root,root)
%license COPYING
%exclude %dir %{_libdir}/debug
/boot/System.map-%{uname_r}
/boot/config-%{uname_r}
/boot/vmlinuz-%{uname_r}
/boot/.vmlinuz-%{uname_r}.hmac
%config(noreplace) /boot/linux-%{uname_r}.cfg
%config %{_localstatedir}/lib/initramfs/kernel/%{uname_r}
%defattr(0644,root,root)
/lib/modules/%{uname_r}/*
/lib/modules/%{uname_r}/.vmlinuz.hmac
%exclude /lib/modules/%{uname_r}/build
%exclude /lib/modules/%{uname_r}/kernel/drivers/accessibility
%exclude /lib/modules/%{uname_r}/kernel/drivers/gpu
%exclude /lib/modules/%{uname_r}/kernel/sound

%files docs
%defattr(-,root,root)
%{_defaultdocdir}/linux-%{uname_r}/*

%files devel
%defattr(-,root,root)
/lib/modules/%{uname_r}/build
%{_prefix}/src/linux-headers-%{uname_r}

%files drivers-accessibility
%defattr(-,root,root)
/lib/modules/%{uname_r}/kernel/drivers/accessibility

%files drivers-sound
%defattr(-,root,root)
/lib/modules/%{uname_r}/kernel/sound

%files tools
%defattr(-,root,root)
%{_libexecdir}
%exclude %dir %{_libdir}/debug
%ifarch x86_64
%{_sbindir}/cpufreq-bench
%{_lib64dir}/traceevent
%{_lib64dir}/libperf-jvmti.so
%{_lib64dir}/libcpupower.so*
%{_sysconfdir}/cpufreq-bench.conf
%{_includedir}/cpuidle.h
%{_includedir}/cpufreq.h
%{_mandir}/man1/cpupower*.gz
%{_mandir}/man8/turbostat*.gz
%{_datadir}/locale/*/LC_MESSAGES/cpupower.mo
%{_datadir}/bash-completion/completions/cpupower
%endif
%{_bindir}
%{_sysconfdir}/bash_completion.d/*
%{_datadir}/perf-core/strace/groups/file
%{_datadir}/perf-core/strace/groups/string
%{_docdir}/*
%{_libdir}/perf/examples/bpf/*
%{_libdir}/perf/include/bpf/*
%{_includedir}/perf/perf_dlfilter.h

%files -n python3-perf
%{python3_sitearch}/*

%files -n bpftool
%{_sbindir}/bpftool
%{_sysconfdir}/bash_completion.d/bpftool

%changelog

* Tue Sep 19 2023 Carolyn Wyborny <carolyn.wyborny@intel.com> - 5.15.1-4
- Add support for Intel E810 devices

* Wed Apr 19 2023 Rachel Menge <rachelmenge@microsoft.com> - 5.15.55.1-3
- Disable rpm's debuginfo defaults which regenerate build-ids

* Tue Sep 13 2022 Saul Paredes <saulparedes@microsoft.com> - 5.15.55.1-2
- Adjust crashkernel param to crash, dump memory to a file, and recover correctly

* Sun Aug 28 2022 Xenofon Foukas <xefouk@microsoft.com> - 5.15.55.1-1
- Update source to 5.15.55.1

* Mon Aug 08 2022 Sriram Nambakam <snambakam@microsoft.com> - 5.15.44.1-6
- Enable CONFIG_PCI_PF_STUB

* Mon Aug 08 2022 Sriram Nambakam <snambakam@microsoft.com> - 5.15.44.1-5
- Enable ICE in-tree driver
- Enable CONFIG_NO_HZ_FULL

* Sun Aug 07 2022 Sriram Nambakam <snambakam@microsoft.com> - 5.15.44.1-4
- Enable CONFIG_VFIO_NOIOMMU for RT Kernel

* Fri Jul 01 2022 Sriram Nambakam <snambakam@microsoft.com> - 5.15.44.1-3
- Build turbostat and cpupower

* Tue Jun 14 2022 Pawel Winogrodzki <pawelwi@microsoft.com> - 5.15.44.1-2
- Updating build steps for the regular kernel.

* Thu Jun 09 2022 Cameron Baird <cameronbaird@microsoft.com> - 5.15.44.1-1
- Update source to 5.15.44.1

* Mon Jun 06 2022 Minghe Ren <mingheren@microsoft.com> - 5.15.34.1-2
- Disable SMACK kernel configuration

* Tue Apr 19 2022 Cameron Baird <cameronbaird@microsoft.com> - 5.15.34.1-1
- Update source to 5.15.34.1

* Tue Apr 19 2022 Max Brodeur-Urbas <maxbr@microsoft.com> - 5.15.32.1-3
- Remove kernel lockdown config from grub envblock

* Tue Apr 12 2022 Andrew Phelps <anphel@microsoft.com> - 5.15.32.1-2
- Remove trace symlink from _bindir
- Exclude files and directories under the debug folder from kernel and kernel-tools packages
- Remove BR for xerces-c-devel

* Fri Apr 08 2022 Neha Agarwal <nehaagarwal@microsoft.com> - 5.15.32.1-1
- Update source to 5.15.32.1

* Tue Apr 05 2022 Henry Li <lihl@microsoft.com> - 5.15.26.1-4
- Add Dell devices support

* Mon Mar 28 2022 Rachel Menge <rachelmenge@microsoft.com> - 5.15.26.1-3
- Remove hardcoded mariner.pem from configs and instead insert during
  the build phase

* Mon Mar 14 2022 Vince Perri <viperri@microsoft.com> - 5.15.26.1-2
- Add support for compressed firmware

* Tue Mar 08 2022 cameronbaird <cameronbaird@microsoft.com> - 5.15.26.1-1
- Update source to 5.15.26.1
- Add some documentation about update process for rt patch

* Thu Feb 24 2022 Cameron Baird <cameronbaird@microsoft.com> - 5.15.18.1-4
- CONFIG_BPF_UNPRIV_DEFAULT_OFF=y
- Bump release number to match kernel release

* Mon Feb 07 2022 Cameron Baird <cameronbaird@microsoft.com> - 5.15.18.1-1
- Update source to 5.15.18.1

* Thu Feb 03 2022 Cameron Baird <cameronbaird@microsoft.com> - 5.15.2.1-4
- Bump release number to match kernel release

* Wed Jan 26 2022 Cameron Baird <cameronbaird@microsoft.com> - 5.15.2.1-2
- Rotate Mariner cert

* Tue Jan 11 2022 Cameron Baird <cameronbaird@microsoft.com> - 5.15.2.1-1
- Create realtime variant of kernel-5.15.2.1
- Remove all references to aarch64

* Thu Jan 06 2022 Rachel Menge <rachelmenge@microsoft.com> - 5.15.2.1-1
- Update source to 5.15.2.1

* Tue Jan 04 2022 Suresh Babu Chalamalasetty <schalam@microsoft.com> - 5.10.78.1-3
- Add provides exclude for debug build-id for aarch64 to generate debuginfo rpm
- Fix missing brackets for __os_install_post.

* Tue Dec 28 2021 Suresh Babu Chalamalasetty <schalam@microsoft.com> - 5.10.78.1-2
- Enable CONFIG_COMPAT kernel configs

* Tue Nov 23 2021 Rachel Menge <rachelmenge@microsoft.com> - 5.10.78.1-1
- Update source to 5.10.78.1
- Address CVE-2021-43267, CVE-2021-42739, CVE-2021-42327, CVE-2021-43389
- Add patch to fix SPDX-License-Identifier in headers

* Mon Nov 15 2021 Thomas Crain <thcrain@microsoft.com> - 5.10.74.1-4
- Add python3-perf subpackage and add python3-devel to build-time requirements
- Exclude accessibility modules from main package to avoid subpackage conflict
- Remove redundant License tag from bpftool subpackage

* Thu Nov 04 2021 Andrew Phelps <anphel@microsoft.com> - 5.10.74.1-3
- Update configs for gcc 11.2.0 and binutils 2.37 updates

* Tue Oct 26 2021 Rachel Menge <rachelmenge@microsoft.com> - 5.10.74.1-2
- Update configs for eBPF support
- Add dwarves Build-requires

* Tue Oct 19 2021 Rachel Menge <rachelmenge@microsoft.com> - 5.10.74.1-1
- Update source to 5.10.74.1
- Address CVE-2021-41864, CVE-2021-42252
- License verified

* Thu Oct 07 2021 Rachel Menge <rachelmenge@microsoft.com> - 5.10.69.1-1
- Update source to 5.10.69.1
- Address CVE-2021-38300, CVE-2021-41073, CVE-2021-3653, CVE-2021-42008

* Wed Sep 22 2021 Rachel Menge <rachelmenge@microsoft.com> - 5.10.64.1-2
- Enable CONFIG_NET_VRF
- Add vrf to drivers argument for dracut

* Mon Sep 20 2021 Rachel Menge <rachelmenge@microsoft.com> - 5.10.64.1-1
- Update source to 5.10.64.1

* Fri Sep 17 2021 Rachel Menge <rachelmenge@microsoft.com> - 5.10.60.1-1
- Remove cn from dracut drivers argument
- Update source to 5.10.60.1
- Address CVE-2021-38166, CVE-2021-38205, CVE-2021-3573
  CVE-2021-37576, CVE-2021-34556, CVE-2021-35477, CVE-2021-28691,
  CVE-2021-3564, CVE-2020-25639, CVE-2021-29657, CVE-2021-38199,
  CVE-2021-38201, CVE-2021-38202, CVE-2021-38207, CVE-2021-38204,
  CVE-2021-38206, CVE-2021-38208, CVE-2021-38200, CVE-2021-38203,
  CVE-2021-38160, CVE-2021-3679, CVE-2021-38198, CVE-2021-38209,
  CVE-2021-3655
- Add patch to fix VDSO in HyperV

* Thu Sep 09 2021 Muhammad Falak <mwani@microsoft.com> - 5.10.52.1-2
- Export `bpftool` subpackage

* Tue Jul 20 2021 Rachel Menge <rachelmenge@microsoft.com> - 5.10.52.1-1
- Update source to 5.10.52.1
- Address CVE-2021-35039, CVE-2021-33909

* Mon Jul 19 2021 Chris Co <chrco@microsoft.com> - 5.10.47.1-2
- Enable CONFIG_CONNECTOR and CONFIG_PROC_EVENTS

* Tue Jul 06 2021 Rachel Menge <rachelmenge@microsoft.com> - 5.10.47.1-1
- Update source to 5.10.47.1
- Address CVE-2021-34693, CVE-2021-33624

* Wed Jun 30 2021 Chris Co <chrco@microsoft.com> - 5.10.42.1-4
- Enable legacy mcelog config

* Tue Jun 22 2021 Suresh Babu Chalamalasetty <schalam@microsoft.com> - 5.10.42.1-3
- Enable CONFIG_IOSCHED_BFQ and CONFIG_BFQ_GROUP_IOSCHED configs

* Wed Jun 16 2021 Chris Co <chrco@microsoft.com> - 5.10.42.1-2
- Enable CONFIG_CROSS_MEMORY_ATTACH

* Tue Jun 08 2021 Rachel Menge <rachelmenge@microsoft.com> - 5.10.42.1-1
- Update source to 5.10.42.1
- Address CVE-2021-33200

* Thu Jun 03 2021 Rachel Menge <rachelmenge@microsoft.com> - 5.10.37.1-2
- Address CVE-2020-25672

* Fri May 28 2021 Rachel Menge <rachelmenge@microsoft.com> - 5.10.37.1-1
- Update source to 5.10.37.1
- Address CVE-2021-23134, CVE-2021-29155, CVE-2021-31829, CVE-2021-31916,
  CVE-2021-32399, CVE-2021-33033, CVE-2021-33034, CVE-2021-3483
  CVE-2021-3501, CVE-2021-3506

* Thu May 27 2021 Chris Co <chrco@microsoft.com> - 5.10.32.1-7
- Set lockdown=integrity by default

* Wed May 26 2021 Chris Co <chrco@microsoft.com> - 5.10.32.1-6
- Add Mariner cert into the trusted kernel keyring

* Tue May 25 2021 Daniel Mihai <dmihai@microsoft.com> - 5.10.32.1-5
- Enable kernel debugger

* Thu May 20 2021 Nicolas Ontiveros <niontive@microsoft.com> - 5.10.32.1-4
- Bump release number to match kernel-signed update

* Mon May 17 2021 Andrew Phelps <anphel@microsoft.com> - 5.10.32.1-3
- Update CONFIG_LD_VERSION for binutils 2.36.1
- Remove build-id match check

* Thu May 13 2021 Rachel Menge <rachelmenge@microsoft.com> - 5.10.32.1-2
- Add CONFIG_AS_HAS_LSE_ATOMICS=y

* Mon May 03 2021 Rachel Menge <rachelmenge@microsoft.com> - 5.10.32.1-1
- Update source to 5.10.32.1
- Address CVE-2021-23133, CVE-2021-29154, CVE-2021-30178

* Thu Apr 22 2021 Chris Co <chrco@microsoft.com> - 5.10.28.1-4
- Disable CONFIG_EFI_DISABLE_PCI_DMA. It can cause boot issues on some hardware.

* Mon Apr 19 2021 Chris Co <chrco@microsoft.com> - 5.10.28.1-3
- Bump release number to match kernel-signed update

* Thu Apr 15 2021 Rachel Menge <rachelmenge@microsoft.com> - 5.10.28.1-2
- Address CVE-2021-29648

* Thu Apr 08 2021 Chris Co <chrco@microsoft.com> - 5.10.28.1-1
- Update source to 5.10.28.1
- Update uname_r define to match the new value derived from the source
- Address CVE-2020-27170, CVE-2020-27171, CVE-2021-28375, CVE-2021-28660,
  CVE-2021-28950, CVE-2021-28951, CVE-2021-28952, CVE-2021-28971,
  CVE-2021-28972, CVE-2021-29266, CVE-2021-28964, CVE-2020-35508,
  CVE-2020-16120, CVE-2021-29264, CVE-2021-29265, CVE-2021-29646,
  CVE-2021-29647, CVE-2021-29649, CVE-2021-29650, CVE-2021-30002

* Fri Mar 26 2021 Daniel Mihai <dmihai@microsoft.com> - 5.10.21.1-4
- Enable CONFIG_CRYPTO_DRBG_HASH, CONFIG_CRYPTO_DRBG_CTR

* Thu Mar 18 2021 Chris Co <chrco@microsoft.com> - 5.10.21.1-3
- Address CVE-2021-27365, CVE-2021-27364, CVE-2021-27363
- Enable CONFIG_FANOTIFY_ACCESS_PERMISSIONS

* Wed Mar 17 2021 Nicolas Ontiveros <niontive@microsoft.com> - 5.10.21.1-2
- Disable QAT kernel configs

* Thu Mar 11 2021 Chris Co <chrco@microsoft.com> - 5.10.21.1-1
- Update source to 5.10.21.1
- Add virtio drivers to be installed into initrd
- Address CVE-2021-26930, CVE-2020-35499, CVE-2021-26931, CVE-2021-26932

* Fri Mar 05 2021 Chris Co <chrco@microsoft.com> - 5.10.13.1-4
- Enable kernel lockdown config

* Thu Mar 04 2021 Suresh Babu Chalamalasetty <schalam@microsoft.com> - 5.10.13.1-3
- Add configs for CONFIG_BNXT bnxt_en and MSR drivers

* Mon Feb 22 2021 Thomas Crain <thcrain@microsoft.com> - 5.10.13.1-2
- Add configs for speakup and uinput drivers
- Add kernel-drivers-accessibility subpackage

* Thu Feb 18 2021 Chris Co <chrco@microsoft.com> - 5.10.13.1-1
- Update source to 5.10.13.1
- Remove patch to publish efi tpm event log on ARM. Present in updated source.
- Remove patch for arm64 hyperv support. Present in updated source.
- Account for new module.lds location on aarch64
- Remove CONFIG_GCC_PLUGIN_RANDSTRUCT
- Add CONFIG_SCSI_SMARTPQI=y

* Thu Feb 11 2021 Nicolas Ontiveros <niontive@microsoft.com> - 5.4.91-5
- Add configs to enable tcrypt in FIPS mode

* Tue Feb 09 2021 Nicolas Ontiveros <niontive@microsoft.com> - 5.4.91-4
- Use OpenSSL to perform HMAC calc

* Thu Jan 28 2021 Nicolas Ontiveros <niontive@microsoft.com> - 5.4.91-3
- Add configs for userspace crypto support
- HMAC calc the kernel for FIPS

* Wed Jan 27 2021 Daniel McIlvaney <damcilva@microsoft.com> - 5.4.91-2
- Enable dm-verity boot support with FEC

* Wed Jan 20 2021 Chris Co <chrco@microsoft.com> - 5.4.91-1
- Update source to 5.4.91
- Address CVE-2020-29569, CVE-2020-28374, CVE-2020-36158
- Remove patch to fix GUI installer crash. Fixed in updated source.

* Tue Jan 12 2021 Rachel Menge <rachelmenge@microsoft.com> - 5.4.83-4
- Add imx8mq support

* Sat Jan 09 2021 Andrew Phelps <anphel@microsoft.com> - 5.4.83-3
- Add patch to fix GUI installer crash

* Mon Dec 28 2020 Nicolas Ontiveros <niontive@microsoft.com> - 5.4.83-2
- Address CVE-2020-27777

* Tue Dec 15 2020 Henry Beberman <henry.beberman@microsoft.com> - 5.4.83-1
- Update source to 5.4.83
- Address CVE-2020-14351, CVE-2020-14381, CVE-2020-25656, CVE-2020-25704,
  CVE-2020-29534, CVE-2020-29660, CVE-2020-29661

* Fri Dec 04 2020 Chris Co <chrco@microsoft.com> - 5.4.81-1
- Update source to 5.4.81
- Remove patch for kexec in HyperV. Integrated in 5.4.81.
- Address CVE-2020-25705, CVE-2020-15436, CVE-2020-28974, CVE-2020-29368,
  CVE-2020-29369, CVE-2020-29370, CVE-2020-29374, CVE-2020-29373, CVE-2020-28915,
  CVE-2020-28941, CVE-2020-27675, CVE-2020-15437, CVE-2020-29371, CVE-2020-29372,
  CVE-2020-27194, CVE-2020-27152

* Wed Nov 25 2020 Chris Co <chrco@microsoft.com> - 5.4.72-5
- Add patch to publish efi tpm event log on ARM

* Mon Nov 23 2020 Chris Co <chrco@microsoft.com> - 5.4.72-4
- Apply patch to fix kexec in HyperV

* Mon Nov 16 2020 Suresh Babu Chalamalasetty <schalam@microsoft.com> - 5.4.72-3
- Disable kernel config SLUB_DEBUG_ON due to tcp throughput perf impact

* Tue Nov 10 2020 Suresh Babu Chalamalasetty <schalam@microsoft.com> - 5.4.72-2
- Enable kernel configs for Arm64 HyperV, Ampere and Cavium SoCs support

* Mon Oct 26 2020 Chris Co <chrco@microsoft.com> - 5.4.72-1
- Update source to 5.4.72
- Remove patch to support CometLake e1000e ethernet. Integrated in 5.4.72.
- Add license file
- Lint spec
- Address CVE-2018-1000026, CVE-2018-16880, CVE-2020-12464, CVE-2020-12465,
  CVE-2020-12659, CVE-2020-15780, CVE-2020-14356, CVE-2020-14386, CVE-2020-25645,
  CVE-2020-25643, CVE-2020-25211, CVE-2020-25212, CVE-2008-4609, CVE-2020-14331,
  CVE-2010-0298, CVE-2020-10690, CVE-2020-25285, CVE-2020-10711, CVE-2019-3887,
  CVE-2020-14390, CVE-2019-19338, CVE-2019-20810, CVE-2020-10766, CVE-2020-10767,
  CVE-2020-10768, CVE-2020-10781, CVE-2020-12768, CVE-2020-14314, CVE-2020-14385,
  CVE-2020-25641, CVE-2020-26088, CVE-2020-10942, CVE-2020-12826, CVE-2019-3016,
  CVE-2019-3819, CVE-2020-16166, CVE-2020-11608, CVE-2020-11609, CVE-2020-25284,
  CVE-2020-12888, CVE-2017-8244, CVE-2017-8245, CVE-2017-8246, CVE-2009-4484,
  CVE-2015-5738, CVE-2007-4998, CVE-2010-0309, CVE-2011-0640, CVE-2020-12656,
  CVE-2011-2519, CVE-1999-0656, CVE-2010-4563, CVE-2019-20794, CVE-1999-0524

* Fri Oct 16 2020 Suresh Babu Chalamalasetty <schalam@microsoft.com> - 5.4.51-11
- Enable QAT kernel configs

* Fri Oct 02 2020 Chris Co <chrco@microsoft.com> - 5.4.51-10
- Address CVE-2020-10757, CVE-2020-12653, CVE-2020-12657, CVE-2010-3865,
  CVE-2020-11668, CVE-2020-12654, CVE-2020-24394, CVE-2020-8428

* Fri Oct 02 2020 Chris Co <chrco@microsoft.com> - 5.4.51-9
- Fix aarch64 build error

* Wed Sep 30 2020 Emre Girgin <mrgirgin@microsoft.com> - 5.4.51-8
- Update postun script to deal with removal in case of another installed kernel.

* Fri Sep 25 2020 Suresh Babu Chalamalasetty <schalam@microsoft.com> - 5.4.51-7
- Enable Mellanox kernel configs

* Wed Sep 23 2020 Daniel McIlvaney <damcilva@microsoft.com> - 5.4.51-6
- Enable CONFIG_IMA (measurement only) and associated configs

* Thu Sep 03 2020 Daniel McIlvaney <damcilva@microsoft.com> - 5.4.51-5
- Add code to check for missing config flags in the checked in configs

* Thu Sep 03 2020 Chris Co <chrco@microsoft.com> - 5.4.51-4
- Apply additional kernel hardening configs

* Thu Sep 03 2020 Chris Co <chrco@microsoft.com> - 5.4.51-3
- Bump release number due to kernel-signed-<arch> package update
- Minor aarch64 config and changelog cleanup

* Tue Sep 01 2020 Chris Co <chrco@microsoft.com> - 5.4.51-2
- Update source hash

* Wed Aug 19 2020 Chris Co <chrco@microsoft.com> - 5.4.51-1
- Update source to 5.4.51
- Enable DXGKRNL config
- Address CVE-2020-11494, CVE-2020-11565, CVE-2020-12655, CVE-2020-12771,
  CVE-2020-13974, CVE-2020-15393, CVE-2020-8647, CVE-2020-8648, CVE-2020-8649,
  CVE-2020-9383, CVE-2020-11725

* Wed Aug 19 2020 Chris Co <chrco@microsoft.com> - 5.4.42-12
- Remove the signed package depends

* Tue Aug 18 2020 Chris Co <chrco@microsoft.com> - 5.4.42-11
- Remove signed subpackage

* Mon Aug 17 2020 Chris Co <chrco@microsoft.com> - 5.4.42-10
- Enable BPF, PC104, userfaultfd, SLUB sysfs, SMC, XDP sockets monitoring configs

* Fri Aug 07 2020 Mateusz Malisz <mamalisz@microsoft.com> - 5.4.42-9
- Add crashkernel=128M to the kernel cmdline
- Update config to support kexec and kexec_file_load

* Tue Aug 04 2020 Pawel Winogrodzki <pawelwi@microsoft.com> - 5.4.42-8
- Updating "KBUILD_BUILD_VERSION" and "KBUILD_BUILD_HOST" with correct
  distribution name.

* Wed Jul 22 2020 Chris Co <chrco@microsoft.com> - 5.4.42-7
- Address CVE-2020-8992, CVE-2020-12770, CVE-2020-13143, CVE-2020-11884

* Fri Jul 17 2020 Suresh Babu Chalamalasetty <schalam@microsoft.com> - 5.4.42-6
- Enable CONFIG_MLX5_CORE_IPOIB and CONFIG_INFINIBAND_IPOIB config flags

* Fri Jul 17 2020 Suresh Babu Chalamalasetty <schalam@microsoft.com> - 5.4.42-5
- Adding XDP config flag

* Thu Jul 09 2020 Anand Muthurajan <anandm@microsoft.com> - 5.4.42-4
- Enable CONFIG_QED, CONFIG_QEDE, CONFIG_QED_SRIOV and CONFIG_QEDE_VXLAN flags

* Wed Jun 24 2020 Chris Co <chrco@microsoft.com> - 5.4.42-3
- Regenerate input config files

* Fri Jun 19 2020 Chris Co <chrco@microsoft.com> - 5.4.42-2
- Add kernel-secure subpackage and macros for adding offline signed kernels

* Fri Jun 12 2020 Chris Co <chrco@microsoft.com> - 5.4.42-1
- Update source to 5.4.42

* Thu Jun 11 2020 Chris Co <chrco@microsoft.com> - 5.4.23-17
- Enable PAGE_POISONING configs
- Disable PROC_KCORE config
- Enable RANDOM_TRUST_CPU config for x86_64

* Fri Jun 05 2020 Suresh Babu Chalamalasetty <schalam@microsoft.com> - 5.4.23-16
- Adding BPF config flags

* Thu Jun 04 2020 Chris Co <chrco@microsoft.com> - 5.4.23-15
- Add config support for USB video class devices

* Wed Jun 03 2020 Nicolas Ontiveros <niontive@microsoft.com> - 5.4.23-14
- Add CONFIG_CRYPTO_XTS=y to config.

* Wed Jun 03 2020 Chris Co <chrco@microsoft.com> - 5.4.23-13
- Add patch to support CometLake e1000e ethernet
- Remove drivers-gpu subpackage
- Inline the initramfs trigger and postun source files
- Remove rpi3 dtb and ls1012 dtb subpackages

* Wed May 27 2020 Chris Co <chrco@microsoft.com> - 5.4.23-12
- Update arm64 security configs
- Disable devmem in x86_64 config

* Tue May 26 2020 Daniel Mihai <dmihai@microsoft.com> - 5.4.23-11
- Disabled Reliable Datagram Sockets protocol (CONFIG_RDS).

* Fri May 22 2020 Emre Girgin <mrgirgin@microsoft.com> - 5.4.23-10
- Change /boot directory permissions to 600.

* Thu May 21 2020 Chris Co <chrco@microsoft.com> - 5.4.23-9
- Update x86_64 security configs

* Wed May 20 2020 Suresh Babu Chalamalasetty <schalam@microsoft.com> - 5.4.23-8
- Adding InfiniBand config flags

* Mon May 11 2020 Anand Muthurajan <anandm@microsoft.com> - 5.4.23-7
- Adding PPP config flags

* Tue Apr 28 2020 Emre Girgin <mrgirgin@microsoft.com> - 5.4.23-6
- Renaming Linux-PAM to pam

* Tue Apr 28 2020 Emre Girgin <mrgirgin@microsoft.com> - 5.4.23-5
- Renaming linux to kernel

* Tue Apr 14 2020 Emre Girgin <mrgirgin@microsoft.com> - 5.4.23-4
- Remove linux-aws and linux-esx references.
- Remove kat_build usage.
- Remove ENA module.

* Fri Apr 10 2020 Emre Girgin <mrgirgin@microsoft.com> - 5.4.23-3
- Remove xml-security-c dependency.

* Wed Apr 08 2020 Nicolas Ontiveros <niontive@microsoft.com> - 5.4.23-2
- Remove toybox and only use coreutils for requires.

* Tue Dec 10 2019 Chris Co <chrco@microsoft.com> - 5.4.23-1
- Update to Microsoft Linux Kernel 5.4.23
- Remove patches
- Update ENA module to 2.1.2 to work with Linux 5.4.23
- Remove xr module
- Remove Xen tmem module from dracut module list to fix initramfs creation
- Add patch to fix missing trans_pgd header in aarch64 build

* Fri Oct 11 2019 Henry Beberman <hebeberm@microsoft.com> - 4.19.52-8
- Enable Hyper-V TPM in config

* Tue Sep 03 2019 Mateusz Malisz <mamalisz@microsoft.com> - 4.19.52-7
- Initial CBL-Mariner import from Photon (license: Apache2).

* Thu Jul 25 2019 Keerthana K <keerthanak@vmware.com> - 4.19.52-6
- Fix postun scriplet.

* Thu Jul 11 2019 Keerthana K <keerthanak@vmware.com> - 4.19.52-5
- Enable kernel configs necessary for BPF Compiler Collection (BCC).

* Wed Jul 10 2019 Srivatsa S. Bhat (VMware) <srivatsa@csail.mit.edu> 4.19.52-4
- Deprecate linux-aws-tools in favor of linux-tools.

* Tue Jul 02 2019 Alexey Makhalov <amakhalov@vmware.com> - 4.19.52-3
- Fix 9p vsock 16bit port issue.

* Thu Jun 20 2019 Tapas Kundu <tkundu@vmware.com> - 4.19.52-2
- Enabled CONFIG_I2C_CHARDEV to support lm-sensors

* Mon Jun 17 2019 Srivatsa S. Bhat (VMware) <srivatsa@csail.mit.edu> 4.19.52-1
- Update to version 4.19.52
- Fix CVE-2019-12456, CVE-2019-12379, CVE-2019-12380, CVE-2019-12381,
- CVE-2019-12382, CVE-2019-12378, CVE-2019-12455

* Tue May 28 2019 Srivatsa S. Bhat (VMware) <srivatsa@csail.mit.edu> 4.19.40-3
- Change default I/O scheduler to 'deadline' to fix performance issue.

* Tue May 14 2019 Keerthana K <keerthanak@vmware.com> - 4.19.40-2
- Fix to parse through /boot folder and update symlink (/boot/photon.cfg) if
- mulitple kernels are installed and current linux kernel is removed.

* Tue May 07 2019 Ajay Kaher <akaher@vmware.com> - 4.19.40-1
- Update to version 4.19.40

* Thu Apr 11 2019 Srivatsa S. Bhat (VMware) <srivatsa@csail.mit.edu> 4.19.32-3
- Update config_aarch64 to fix ARM64 build.

* Fri Mar 29 2019 Srivatsa S. Bhat (VMware) <srivatsa@csail.mit.edu> 4.19.32-2
- Fix CVE-2019-10125

* Wed Mar 27 2019 Srivatsa S. Bhat (VMware) <srivatsa@csail.mit.edu> 4.19.32-1
- Update to version 4.19.32

* Thu Mar 14 2019 Srivatsa S. Bhat (VMware) <srivatsa@csail.mit.edu> 4.19.29-1
- Update to version 4.19.29

* Tue Mar 05 2019 Ajay Kaher <akaher@vmware.com> - 4.19.26-1
- Update to version 4.19.26

* Thu Feb 21 2019 Him Kalyan Bordoloi <bordoloih@vmware.com> - 4.19.15-3
- Fix CVE-2019-8912

* Thu Jan 24 2019 Alexey Makhalov <amakhalov@vmware.com> - 4.19.15-2
- Add WiFi (ath10k), sensors (i2c,spi), usb support for NXP LS1012A board.

* Tue Jan 15 2019 Srivatsa S. Bhat (VMware) <srivatsa@csail.mit.edu> 4.19.15-1
- Update to version 4.19.15

* Fri Jan 11 2019 Srinidhi Rao <srinidhir@vmware.com> - 4.19.6-7
- Add Network support for NXP LS1012A board.

* Wed Jan 09 2019 Ankit Jain <ankitja@vmware.com> - 4.19.6-6
- Enable following for x86_64 and aarch64:
-  Enable Kernel Address Space Layout Randomization.
-  Enable CONFIG_SECURITY_NETWORK_XFRM

* Fri Jan 04 2019 Srivatsa S. Bhat (VMware) <srivatsa@csail.mit.edu> 4.19.6-5
- Enable AppArmor by default.

* Wed Jan 02 2019 Alexey Makhalov <amakhalov@vmware.com> - 4.19.6-4
- .config: added Compulab fitlet2 device drivers
- .config_aarch64: added gpio sysfs support
- renamed -sound to -drivers-sound

* Tue Jan 01 2019 Ajay Kaher <akaher@vmware.com> - 4.19.6-3
- .config: Enable CONFIG_PCI_HYPERV driver

* Wed Dec 19 2018 Srinidhi Rao <srinidhir@vmware.com> - 4.19.6-2
- Add NXP LS1012A support.

* Mon Dec 10 2018 Srivatsa S. Bhat (VMware) <srivatsa@csail.mit.edu> 4.19.6-1
- Update to version 4.19.6

* Fri Dec 07 2018 Alexey Makhalov <amakhalov@vmware.com> - 4.19.1-3
- .config: added qmi wwan module

* Mon Nov 12 2018 Ajay Kaher <akaher@vmware.com> - 4.19.1-2
- Fix config_aarch64 for 4.19.1

* Mon Nov 05 2018 Srivatsa S. Bhat (VMware) <srivatsa@csail.mit.edu> 4.19.1-1
- Update to version 4.19.1

* Tue Oct 16 2018 Him Kalyan Bordoloi <bordoloih@vmware.com> - 4.18.9-5
- Change in config to enable drivers for zigbee and GPS

* Fri Oct 12 2018 Ajay Kaher <akaher@vmware.com> - 4.18.9-4
- Enable LAN78xx for aarch64 rpi3

* Fri Oct 5 2018 Ajay Kaher <akaher@vmware.com> - 4.18.9-3
- Fix config_aarch64 for 4.18.9
- Add module.lds for aarch64

* Wed Oct 03 2018 Srivatsa S. Bhat <srivatsa@csail.mit.edu> 4.18.9-2
- Use updated steal time accounting patch.
- .config: Enable CONFIG_CPU_ISOLATION and a few networking options
- that got accidentally dropped in the last update.

* Mon Oct 1 2018 Srivatsa S. Bhat <srivatsa@csail.mit.edu> 4.18.9-1
- Update to version 4.18.9

* Tue Sep 25 2018 Ajay Kaher <akaher@vmware.com> - 4.14.67-2
- Build hang (at make oldconfig) fix in config_aarch64

* Wed Sep 19 2018 Srivatsa S. Bhat <srivatsa@csail.mit.edu> 4.14.67-1
- Update to version 4.14.67

* Tue Sep 18 2018 Srivatsa S. Bhat <srivatsa@csail.mit.edu> 4.14.54-7
- Add rdrand-based RNG driver to enhance kernel entropy.

* Sun Sep 02 2018 Srivatsa S. Bhat <srivatsa@csail.mit.edu> 4.14.54-6
- Add full retpoline support by building with retpoline-enabled gcc.

* Thu Aug 30 2018 Srivatsa S. Bhat <srivatsa@csail.mit.edu> 4.14.54-5
- Apply out-of-tree patches needed for AppArmor.

* Wed Aug 22 2018 Alexey Makhalov <amakhalov@vmware.com> - 4.14.54-4
- Fix overflow kernel panic in rsi driver.
- .config: enable BT stack, enable GPIO sysfs.
- Add Exar USB serial driver.

* Fri Aug 17 2018 Ajay Kaher <akaher@vmware.com> - 4.14.54-3
- Enabled USB PCI in config_aarch64
- Build hang (at make oldconfig) fix in config_aarch64

* Thu Jul 19 2018 Alexey Makhalov <amakhalov@vmware.com> - 4.14.54-2
- .config: usb_serial_pl2303=m,wlan=y,can=m,gpio=y,pinctrl=y,iio=m

* Mon Jul 09 2018 Him Kalyan Bordoloi <bordoloih@vmware.com> - 4.14.54-1
- Update to version 4.14.54

* Fri Jan 26 2018 Alexey Makhalov <amakhalov@vmware.com> - 4.14.8-2
- Added vchiq entry to rpi3 dts
- Added dtb-rpi3 subpackage

* Fri Dec 22 2017 Alexey Makhalov <amakhalov@vmware.com> - 4.14.8-1
- Version update

* Wed Dec 13 2017 Alexey Makhalov <amakhalov@vmware.com> - 4.9.66-4
- KAT build support

* Thu Dec 07 2017 Alexey Makhalov <amakhalov@vmware.com> - 4.9.66-3
- Aarch64 support

* Tue Dec 05 2017 Alexey Makhalov <amakhalov@vmware.com> - 4.9.66-2
- Sign and compress modules after stripping. fips=1 requires signed modules

* Mon Dec 04 2017 Srivatsa S. Bhat <srivatsa@csail.mit.edu> 4.9.66-1
- Version update

* Tue Nov 21 2017 Srivatsa S. Bhat <srivatsa@csail.mit.edu> 4.9.64-1
- Version update

* Mon Nov 06 2017 Srivatsa S. Bhat <srivatsa@csail.mit.edu> 4.9.60-1
- Version update

* Wed Oct 11 2017 Srivatsa S. Bhat <srivatsa@csail.mit.edu> 4.9.53-3
- Add patch "KVM: Don't accept obviously wrong gsi values via
    KVM_IRQFD" to fix CVE-2017-1000252.

* Tue Oct 10 2017 Alexey Makhalov <amakhalov@vmware.com> - 4.9.53-2
- Build hang (at make oldconfig) fix.

* Thu Oct 05 2017 Srivatsa S. Bhat <srivatsa@csail.mit.edu> 4.9.53-1
- Version update

* Mon Oct 02 2017 Srivatsa S. Bhat <srivatsa@csail.mit.edu> 4.9.52-3
- Allow privileged CLONE_NEWUSER from nested user namespaces.

* Mon Oct 02 2017 Srivatsa S. Bhat <srivatsa@csail.mit.edu> 4.9.52-2
- Fix CVE-2017-11472 (ACPICA: Namespace: fix operand cache leak)

* Mon Oct 02 2017 Srivatsa S. Bhat <srivatsa@csail.mit.edu> 4.9.52-1
- Version update

* Mon Sep 18 2017 Alexey Makhalov <amakhalov@vmware.com> - 4.9.47-2
- Requires coreutils or toybox

* Mon Sep 04 2017 Alexey Makhalov <amakhalov@vmware.com> - 4.9.47-1
- Fix CVE-2017-11600

* Tue Aug 22 2017 Anish Swaminathan <anishs@vmware.com> - 4.9.43-2
- Add missing xen block drivers

* Mon Aug 14 2017 Alexey Makhalov <amakhalov@vmware.com> - 4.9.43-1
- Version update
- [feature] new sysctl option unprivileged_userns_clone

* Wed Aug 09 2017 Alexey Makhalov <amakhalov@vmware.com> - 4.9.41-2
- Fix CVE-2017-7542
- [bugfix] Added ccm,gcm,ghash,lzo crypto modules to avoid
    panic on modprobe tcrypt

* Mon Aug 07 2017 Alexey Makhalov <amakhalov@vmware.com> - 4.9.41-1
- Version update

* Fri Aug 04 2017 Bo Gan <ganb@vmware.com> - 4.9.38-6
- Fix initramfs triggers

* Tue Aug 01 2017 Anish Swaminathan <anishs@vmware.com> - 4.9.38-5
- Allow some algorithms in FIPS mode
- Reverts 284a0f6e87b0721e1be8bca419893902d9cf577a and backports
- bcf741cb779283081db47853264cc94854e7ad83 in the kernel tree
- Enable additional NF features

* Fri Jul 21 2017 Anish Swaminathan <anishs@vmware.com> - 4.9.38-4
- Add patches in Hyperv codebase

* Fri Jul 21 2017 Anish Swaminathan <anishs@vmware.com> - 4.9.38-3
- Add missing hyperv drivers

* Thu Jul 20 2017 Alexey Makhalov <amakhalov@vmware.com> - 4.9.38-2
- Disable scheduler beef up patch

* Tue Jul 18 2017 Alexey Makhalov <amakhalov@vmware.com> - 4.9.38-1
- Fix CVE-2017-11176 and CVE-2017-10911

* Mon Jul 03 2017 Xiaolin Li <xiaolinl@vmware.com> - 4.9.34-3
- Add libdnet-devel, kmod-devel and libmspack-devel to BuildRequires

* Thu Jun 29 2017 Divya Thaluru <dthaluru@vmware.com> - 4.9.34-2
- Added obsolete for deprecated linux-dev package

* Wed Jun 28 2017 Alexey Makhalov <amakhalov@vmware.com> - 4.9.34-1
- [feature] 9P FS security support
- [feature] DM Delay target support
- Fix CVE-2017-1000364 ("stack clash") and CVE-2017-9605

* Thu Jun 8 2017 Alexey Makhalov <amakhalov@vmware.com> - 4.9.31-1
- Fix CVE-2017-8890, CVE-2017-9074, CVE-2017-9075, CVE-2017-9076
    CVE-2017-9077 and CVE-2017-9242
- [feature] IPV6 netfilter NAT table support

* Fri May 26 2017 Alexey Makhalov <amakhalov@vmware.com> - 4.9.30-1
- Added ENA driver for AMI
- Fix CVE-2017-7487 and CVE-2017-9059

* Wed May 17 2017 Vinay Kulkarni <kulkarniv@vmware.com> - 4.9.28-2
- Enable IPVLAN module.

* Tue May 16 2017 Alexey Makhalov <amakhalov@vmware.com> - 4.9.28-1
- Version update

* Wed May 10 2017 Alexey Makhalov <amakhalov@vmware.com> - 4.9.27-1
- Version update

* Sun May 7 2017 Alexey Makhalov <amakhalov@vmware.com> - 4.9.26-1
- Version update
- Removed version suffix from config file name

* Thu Apr 27 2017 Bo Gan <ganb@vmware.com> - 4.9.24-2
- Support dynamic initrd generation

* Tue Apr 25 2017 Alexey Makhalov <amakhalov@vmware.com> - 4.9.24-1
- Fix CVE-2017-6874 and CVE-2017-7618.
- Fix audit-devel BuildRequires.
- .config: build nvme and nvme-core in kernel.

* Mon Mar 6 2017 Alexey Makhalov <amakhalov@vmware.com> - 4.9.13-2
- .config: NSX requirements for crypto and netfilter

* Tue Feb 28 2017 Alexey Makhalov <amakhalov@vmware.com> - 4.9.13-1
- Update to linux-4.9.13 to fix CVE-2017-5986 and CVE-2017-6074

* Thu Feb 09 2017 Alexey Makhalov <amakhalov@vmware.com> - 4.9.9-1
- Update to linux-4.9.9 to fix CVE-2016-10153, CVE-2017-5546,
    CVE-2017-5547, CVE-2017-5548 and CVE-2017-5576.
- .config: added CRYPTO_FIPS support.

* Tue Jan 10 2017 Alexey Makhalov <amakhalov@vmware.com> - 4.9.2-1
- Update to linux-4.9.2 to fix CVE-2016-10088
- Move linux-tools.spec to linux.spec as -tools subpackage

* Mon Dec 19 2016 Xiaolin Li <xiaolinl@vmware.com> - 4.9.0-2
- BuildRequires Linux-PAM-devel

* Mon Dec 12 2016 Alexey Makhalov <amakhalov@vmware.com> - 4.9.0-1
- Update to linux-4.9.0
- Add paravirt stolen time accounting feature (from linux-esx),
    but disable it by default (no-vmw-sta cmdline parameter)

* Thu Dec  8 2016 Alexey Makhalov <amakhalov@vmware.com> - 4.4.35-3
- net-packet-fix-race-condition-in-packet_set_ring.patch
    to fix CVE-2016-8655

* Wed Nov 30 2016 Alexey Makhalov <amakhalov@vmware.com> - 4.4.35-2
- Expand `uname -r` with release number
- Check for build-id matching
- Added syscalls tracing support
- Compress modules

* Mon Nov 28 2016 Alexey Makhalov <amakhalov@vmware.com> - 4.4.35-1
- Update to linux-4.4.35
- vfio-pci-fix-integer-overflows-bitmask-check.patch
    to fix CVE-2016-9083

* Tue Nov 22 2016 Alexey Makhalov <amakhalov@vmware.com> - 4.4.31-4
- net-9p-vsock.patch

* Thu Nov 17 2016 Alexey Makhalov <amakhalov@vmware.com> - 4.4.31-3
- tty-prevent-ldisc-drivers-from-re-using-stale-tty-fields.patch
    to fix CVE-2015-8964

* Tue Nov 15 2016 Alexey Makhalov <amakhalov@vmware.com> - 4.4.31-2
- .config: add cgrup_hugetlb support
- .config: add netfilter_xt_{set,target_ct} support
- .config: add netfilter_xt_match_{cgroup,ipvs} support

* Thu Nov 10 2016 Alexey Makhalov <amakhalov@vmware.com> - 4.4.31-1
- Update to linux-4.4.31

* Fri Oct 21 2016 Alexey Makhalov <amakhalov@vmware.com> - 4.4.26-1
- Update to linux-4.4.26

* Wed Oct 19 2016 Alexey Makhalov <amakhalov@vmware.com> - 4.4.20-6
- net-add-recursion-limit-to-GRO.patch
- scsi-arcmsr-buffer-overflow-in-arcmsr_iop_message_xfer.patch

* Tue Oct 18 2016 Alexey Makhalov <amakhalov@vmware.com> - 4.4.20-5
- ipip-properly-mark-ipip-GRO-packets-as-encapsulated.patch
- tunnels-dont-apply-GRO-to-multiple-layers-of-encapsulation.patch

* Mon Oct  3 2016 Alexey Makhalov <amakhalov@vmware.com> - 4.4.20-4
- Package vmlinux with PROGBITS sections in -debuginfo subpackage

* Tue Sep 27 2016 Alexey Makhalov <amakhalov@vmware.com> - 4.4.20-3
- .config: CONFIG_IP_SET_HASH_{IPMARK,MAC}=m

* Tue Sep 20 2016 Alexey Makhalov <amakhalov@vmware.com> - 4.4.20-2
- Add -release number for /boot/* files
- Use initrd.img with version and release number
- Rename -dev subpackage to -devel

* Wed Sep  7 2016 Alexey Makhalov <amakhalov@vmware.com> - 4.4.20-1
- Update to linux-4.4.20
- apparmor-fix-oops-validate-buffer-size-in-apparmor_setprocattr.patch
- keys-fix-asn.1-indefinite-length-object-parsing.patch

* Thu Aug 25 2016 Alexey Makhalov <amakhalov@vmware.com> - 4.4.8-11
- vmxnet3 patches to bumpup a version to 1.4.8.0

* Wed Aug 10 2016 Alexey Makhalov <amakhalov@vmware.com> - 4.4.8-10
- Added VSOCK-Detach-QP-check-should-filter-out-non-matching-QPs.patch
- .config: pmem hotplug + ACPI NFIT support
- .config: enable EXPERT mode, disable UID16 syscalls

* Thu Jul 07 2016 Alexey Makhalov <amakhalov@vmware.com> - 4.4.8-9
- .config: pmem + fs_dax support

* Fri Jun 17 2016 Alexey Makhalov <amakhalov@vmware.com> - 4.4.8-8
- patch: e1000e-prevent-div-by-zero-if-TIMINCA-is-zero.patch
- .config: disable rt group scheduling - not supported by systemd

* Wed Jun 15 2016 Harish Udaiya Kumar <hudaiyakumar@vmware.com> - 4.4.8-7
- fixed the capitalization for - System.map

* Thu May 26 2016 Alexey Makhalov <amakhalov@vmware.com> - 4.4.8-6
- patch: REVERT-sched-fair-Beef-up-wake_wide.patch

* Tue May 24 2016 Priyesh Padmavilasom <ppadmavilasom@vmware.com> - 4.4.8-5
- GA - Bump release of all rpms

* Mon May 23 2016 Harish Udaiya Kumar <hudaiyakumar@vmware.com> - 4.4.8-4
- Fixed generation of debug symbols for kernel modules & vmlinux.

* Mon May 23 2016 Divya Thaluru <dthaluru@vmware.com> - 4.4.8-3
- Added patches to fix CVE-2016-3134, CVE-2016-3135

* Wed May 18 2016 Harish Udaiya Kumar <hudaiyakumar@vmware.com> - 4.4.8-2
- Enabled CONFIG_UPROBES in config as needed by ktap

* Wed May 04 2016 Alexey Makhalov <amakhalov@vmware.com> - 4.4.8-1
- Update to linux-4.4.8
- Added net-Drivers-Vmxnet3-set-... patch

* Tue May 03 2016 Vinay Kulkarni <kulkarniv@vmware.com> - 4.2.0-27
- Compile Intel GigE and VMXNET3 as part of kernel.

* Thu Apr 28 2016 Nick Shi <nshi@vmware.com> - 4.2.0-26
- Compile cramfs.ko to allow mounting cramfs image

* Tue Apr 12 2016 Vinay Kulkarni <kulkarniv@vmware.com> - 4.2.0-25
- Revert network interface renaming disable in kernel.

* Tue Mar 29 2016 Alexey Makhalov <amakhalov@vmware.com> - 4.2.0-24
- Support kmsg dumping to vmware.log on panic
- sunrpc: xs_bind uses ip_local_reserved_ports

* Mon Mar 28 2016 Harish Udaiya Kumar <hudaiyakumar@vmware.com> - 4.2.0-23
- Enabled Regular stack protection in Linux kernel in config

* Thu Mar 17 2016 Harish Udaiya Kumar <hudaiyakumar@vmware.com> - 4.2.0-22
- Restrict the permissions of the /boot/System.map-X file

* Fri Mar 04 2016 Alexey Makhalov <amakhalov@vmware.com> - 4.2.0-21
- Patch: SUNRPC: Do not reuse srcport for TIME_WAIT socket.

* Wed Mar 02 2016 Alexey Makhalov <amakhalov@vmware.com> - 4.2.0-20
- Patch: SUNRPC: Ensure that we wait for connections to complete
    before retrying

* Fri Feb 26 2016 Alexey Makhalov <amakhalov@vmware.com> - 4.2.0-19
- Disable watchdog under VMware hypervisor.

* Thu Feb 25 2016 Alexey Makhalov <amakhalov@vmware.com> - 4.2.0-18
- Added rpcsec_gss_krb5 and nfs_fscache

* Mon Feb 22 2016 Alexey Makhalov <amakhalov@vmware.com> - 4.2.0-17
- Added sysctl param to control weighted_cpuload() behavior

* Thu Feb 18 2016 Divya Thaluru <dthaluru@vmware.com> - 4.2.0-16
- Disabling network renaming

* Sun Feb 14 2016 Alexey Makhalov <amakhalov@vmware.com> - 4.2.0-15
- veth patch: don’t modify ip_summed

* Thu Feb 11 2016 Alexey Makhalov <amakhalov@vmware.com> - 4.2.0-14
- Full tickless -> idle tickless + simple CPU time accounting
- SLUB -> SLAB
- Disable NUMA balancing
- Disable stack protector
- No build_forced no-CBs CPUs
- Disable Expert configuration mode
- Disable most of debug features from 'Kernel hacking'

* Mon Feb 08 2016 Alexey Makhalov <amakhalov@vmware.com> - 4.2.0-13
- Double tcp_mem limits, patch is added.

* Wed Feb 03 2016 Anish Swaminathan <anishs@vmware.com> -  4.2.0-12
- Fixes for CVE-2015-7990/6937 and CVE-2015-8660.

* Tue Jan 26 2016 Anish Swaminathan <anishs@vmware.com> - 4.2.0-11
- Revert CONFIG_HZ=250

* Fri Jan 22 2016 Alexey Makhalov <amakhalov@vmware.com> - 4.2.0-10
- Fix for CVE-2016-0728

* Wed Jan 13 2016 Alexey Makhalov <amakhalov@vmware.com> - 4.2.0-9
- CONFIG_HZ=250

* Tue Jan 12 2016 Mahmoud Bassiouny <mbassiouny@vmware.com> - 4.2.0-8
- Remove rootfstype from the kernel parameter.

* Mon Jan 04 2016 Harish Udaiya Kumar <hudaiyakumar@vmware.com> - 4.2.0-7
- Disabled all the tracing options in kernel config.
- Disabled preempt.
- Disabled sched autogroup.

* Thu Dec 17 2015 Harish Udaiya Kumar <hudaiyakumar@vmware.com> - 4.2.0-6
- Enabled kprobe for systemtap & disabled dynamic function tracing in config

* Fri Dec 11 2015 Harish Udaiya Kumar <hudaiyakumar@vmware.com> - 4.2.0-5
- Added oprofile kernel driver sub-package.

* Fri Nov 13 2015 Mahmoud Bassiouny <mbassiouny@vmware.com> - 4.2.0-4
- Change the linux image directory.

* Wed Nov 11 2015 Harish Udaiya Kumar <hudaiyakumar@vmware.com> - 4.2.0-3
- Added the build essential files in the dev sub-package.

* Mon Nov 09 2015 Vinay Kulkarni <kulkarniv@vmware.com> - 4.2.0-2
- Enable Geneve module support for generic kernel.

* Fri Oct 23 2015 Harish Udaiya Kumar <hudaiyakumar@vmware.com> - 4.2.0-1
- Upgraded the generic linux kernel to version 4.2.0 & and updated timer handling to full tickless mode.

* Tue Sep 22 2015 Harish Udaiya Kumar <hudaiyakumar@vmware.com> - 4.0.9-5
- Added driver support for frame buffer devices and ACPI

* Wed Sep 2 2015 Alexey Makhalov <amakhalov@vmware.com> - 4.0.9-4
- Added mouse ps/2 module.

* Fri Aug 14 2015 Alexey Makhalov <amakhalov@vmware.com> - 4.0.9-3
- Use photon.cfg as a symlink.

* Thu Aug 13 2015 Alexey Makhalov <amakhalov@vmware.com> - 4.0.9-2
- Added environment file(photon.cfg) for grub.

* Wed Aug 12 2015 Sharath George <sharathg@vmware.com> - 4.0.9-1
- Upgrading kernel version.

* Wed Aug 12 2015 Alexey Makhalov <amakhalov@vmware.com> - 3.19.2-5
- Updated OVT to version 10.0.0.
- Rename -gpu-drivers to -drivers-gpu in accordance to directory structure.
- Added -sound package/

* Tue Aug 11 2015 Anish Swaminathan<anishs@vmware.com> - 3.19.2-4
- Removed Requires dependencies.

* Fri Jul 24 2015 Harish Udaiya Kumar <hudaiyakumar@gmail.com> - 3.19.2-3
- Updated the config file to include graphics drivers.

* Mon May 18 2015 Touseef Liaqat <tliaqat@vmware.com> - 3.13.3-2
- Update according to UsrMove.

* Wed Nov 5 2014 Divya Thaluru <dthaluru@vmware.com> - 3.13.3-1
- Initial build. First version
