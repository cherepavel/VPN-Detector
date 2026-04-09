# Android VPN Detector

Research tool for analyzing VPN detection mechanisms on Android.

## Features
- Detect VPN via NetworkCapabilities.TRANSPORT_VPN
- Analyze active vs global VPN state
- Interface detection (tun0, wg0)
- Native + Java network enumeration

## Purpose

Demonstrates how apps can detect VPN presence even with split tunneling.

## Permissions

* `android.permission.ACCESS_NETWORK_STATE` — used to access network state via `ConnectivityManager`
* `android.permission.QUERY_ALL_PACKAGES` — used to enumerate installed applications in order to detect known VPN clients

## Screenshots

**_VPN Active (full tunnel)_**

![](img/vpn_active.jpg)

**_VPN Split / Bypass (still detectable)_**

![](img/vpn_split_bypass.jpg)

## License

MIT
