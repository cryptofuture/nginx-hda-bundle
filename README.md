## Nginx HDA Bundle - Dynamic Modules Power

  > [Snap package](https://github.com/cryptofuture/nginx-hda-bundle-snap) is now available!
  
  > Snap package mainly created for use in distributions outside Ubuntu family.
  
  > [![Get it from the Snap Store](https://snapcraft.io/static/images/badges/en/snap-store-white.svg)](https://snapcraft.io/nginx-hda-bundle)
  
### Add and install from PPA

PPA is located [here](https://launchpad.net/~hda-me/+archive/ubuntu/nginx-stable)

You can add and install any available module with:

```bash
sudo apt-add-repository ppa:hda-me/nginx-stable
sudo apt-get update
sudo apt-get install nginx nginx-module-name-you-wish
```

Package names: `nginx`, `nginx-dbg`, `nginx-module-brotli`, `nginx-module-cache-purge`, `nginx-module-ct`, `nginx-module-devel-kit`, `nginx-module-fancyindex`, `nginx-module-geoip`, `nginx-module-graphite`, `nginx-module-http-auth-pam`, `nginx-module-http-echo`, `nginx-module-http-headers-more`, `nginx-module-http-subs-filter`, `nginx-module-image-filter`, `nginx-module-lenght-hiding-filter`, `nginx-module-lua`, `nginx-module-mail`, `nginx-module-naxsi`, `nginx-module-nchan`, `nginx-module-njs`, `nginx-module-pagespeed`, `nginx-module-perl`, `nginx-module-rds-json`, `nginx-module-rtmp`, `nginx-module-session-binding-proxy`, `nginx-module-stream`, `nginx-module-stream-sts`, `nginx-module-sts`, `nginx-module-testcookie`, `nginx-module-ts`, `nginx-module-upload-progress`, `nginx-module-upstream-fair`, `nginx-module-upstream-order`, `nginx-module-vts`, `nginx-module-xslt`

Add the following to the top of `/etc/nginx/nginx.conf` (for example after pid) and reload nginx

> Note: Use only modules you need to use. With dynamic modules this is pretty easy.

```bash
load_module modules/ndk_http_module.so;
load_module modules/ngx_http_geoip_module.so;
load_module modules/ngx_stream_geoip_module.so;
load_module modules/ngx_http_headers_more_filter_module.so;
load_module modules/ngx_http_image_filter_module.so;
load_module modules/ngx_http_length_hiding_filter_module.so;
load_module modules/ngx_http_lua_module.so;
load_module modules/ngx_http_naxsi_module.so;
load_module modules/ngx_http_js_module.so;
load_module modules/ngx_stream_js_module.so;
load_module modules/ngx_pagespeed.so;
load_module modules/ngx_http_perl_module.so;
load_module modules/ngx_stream_module.so;
load_module modules/ngx_mail_module.so;
load_module modules/ngx_http_rds_json_filter_module.so;
load_module modules/ngx_http_session_binding_proxy_module.so;
load_module modules/ngx_http_testcookie_access_module.so;
load_module modules/ngx_http_upstream_order_module.so;
load_module modules/ngx_http_xslt_filter_module.so;
# ngx_brotli filter module - used to compress responses on-the-fly.
load_module modules/ngx_http_brotli_filter_module.so;
# ngx_brotli static module - used to serve pre-compressed files.
# Both ngx_brotli modules could be used separately, but part of nginx-module-brotli package
load_module modules/ngx_http_brotli_static_module.so;
load_module modules/ngx_postgres_module.so;
load_module modules/ngx_nchan_module.so;
load_module modules/ngx_http_auth_pam_module.so;
load_module modules/ngx_http_echo_module.so;
load_module modules/ngx_http_upstream_fair_module.so;
load_module modules/ngx_http_cache_purge_module.so;
load_module modules/ngx_http_fancyindex_module.so;
load_module modules/ngx_http_uploadprogress_module.so;
load_module modules/ngx_http_subs_filter_module.so;
load_module modules/ngx_http_graphite_module.so;
load module modules/ngx_http_vhost_traffic_status_module.so;
load_module modules/ngx_ssl_ct_module.so 
load_module modules/ngx_http_ssl_ct_module.so 
load_module modules/ngx_mail_ssl_ct_module.so 
load_module modules/ngx_stream_ssl_ct_module.so
load_module modules/ngx_rtmp_module.so;
load_module modules/ngx_http_ts_module.so.so;
load_module modules/ngx_http_stream_server_traffic_status_module.so;
load_module modules/ngx_stream_server_traffic_status_module.so;
```

### Donation

Consider making a donation, if you like what I doing.

I working remotely and income is unstable, so every little bit helps.

Also it would be nice if you provide, a note on `admin@hda.me` after making a donation with information what you like and what you want to improve. So, I would consider giving more time and support to particular project.

I also open to resonable work offers, especially if offer would be close to a field or project I work with.

#### E-money & Fiat

##### Yandex Money
[![Donation on Yandex Money](https://money.yandex.ru/i/shop/apple-touch-icon-72x72.png)](https://money.yandex.ru/to/410015241627045)
##### Advanced Cash
[Open](https://wallet.advcash.com/pages/transfer/wallet) and use `mmail@sent.com` in `Specify the recipient's wallet or e-mail` field
##### PayPal
[![Donation with PayPal](https://www.paypalobjects.com/webstatic/icon/pp72.png)](https://paypal.me/hdadonation)
##### Payeer
[![Donation with Payeer](https://payeer.com/bitrix/templates/difiz_account_new/img/logo-img.svg)](https://payeer.com/en/account/send/) use `P2865115` in `Account, e-mail or phone number` field

#### Cryptocurrency

##### Bitcoin
Address is `1N5czHaoSLukFSTq2ZJujaWGjkmBxv2dT9`
##### Musicoin 
Address is `0xf449f8c17a056e9bfbefe39637c38806246cb2c9`
##### Ethereum
Address is `0x23459a89eAc054bdAC1c13eB5cCb39F42574C26a`
##### Other 
I could provide you with some relatively cheap "hardware" donation options directly to my PO Box, if you prefer real gifts. Ask for details on `admin@hda.me`

### Modules and changes overview:

Every 3rd party module is connected as submodule to the repository. So you could check `.gitmodules` for module source, including exact branch. Some modules under `https://github.com/cryptofuture/*` are forks, and its made only when upstream doesn't accept some useful patch/pr, or when upstream is not maintained and module is patched to make it buildable as dynamic module or buildable with a newer nginx versions.

#### Dynamic modules
- [headers-more-nginx](https://github.com/openresty/headers-more-nginx-module)
- [lua-nginx](https://github.com/openresty/lua-nginx-module), source [used](https://github.com/cryptofuture/lua-nginx-module) with branch `graphite`
- [nginx-length-hiding-filter](https://github.com/nulab/nginx-length-hiding-filter-module)
- [ngx_devel_kit](https://github.com/simpl/ngx_devel_kit)
- [nginx-upstream-order](https://github.com/flygoast/ngx_http_upstream_order)
- [ngx_pagespeed](https://github.com/pagespeed/ngx_pagespeed)
- [rds-json-nginx](https://github.com/openresty/rds-json-nginx-module), source [used](https://github.com/cryptofuture/rds-json-nginx-module) with branch `pull4`
- [njs](https://github.com/nginx/njs)
- [nchan](https://github.com/slact/nchan)
- [ngx-http-auth-pam](https://github.com/sto/ngx_http_auth_pam_module)
- [echo-nginx-module](https://github.com/openresty/echo-nginx-module)
- [nginx-upstream-fair](https://github.com/gnosek/nginx-upstream-fair), source [used](https://github.com/cryptofuture/nginx-upstream-fair)
- [ngx-fancyindex](https://github.com/aperezdc/ngx-fancyindex/)
- [nginx-upload-progress](https://github.com/masterzen/nginx-upload-progress-module)
- [ngx_http_substitutions_filter_module](https://github.com/yaoweibin/ngx_http_substitutions_filter_module), source [used](https://github.com/cryptofuture/ngx_http_substitutions_filter_module)
- [graphite-nginx-module](https://github.com/mailru/graphite-nginx-module)
- [nginx-module-vts](https://github.com/vozlt/nginx-module-vts)
- [nginx-module-ct](https://github.com/grahamedgecombe/nginx-ct)
- [naxsi](https://github.com/nbs-system/naxsi), source [used](https://github.com/cryptofuture/naxsi)
- [ngx_postgres module (commumity fork)](https://github.com/konstruxi/ngx_postgres)
- [ngx_cache_purge](https://github.com/nginx-modules/ngx_cache_purge)
- [nginx-module-ts](https://github.com/arut/nginx-ts-module)
- [nginx-module-rtmp](https://github.com/sergey-dryabzhinsky/nginx-rtmp-module)
- [ngx_brotli](https://github.com/eustas/ngx_brotli):
     - ngx_brotli filter module
     - ngx_brotli static module
- [nginx-module-sts](https://github.com/vozlt/nginx-module-sts)
- [nginx-module-stream-sts](https://github.com/vozlt/nginx-module-stream-sts)
- [testcookie-nginx](https://github.com/kyprizel/testcookie-nginx-module)
- [Session-Binding-Proxy](https://github.com/wburgers/Session-Binding-Proxy)

#### Base dynamic modules
- http_xslt module
- http_image_filter module
- http_geoip module
- http_perl module
- ngx_mail module with xmmp patch (linked with mail_ssl)
- ngx_stream module (linked with stream_ssl), and stream_ssl_preread since 1.11.5.

#### Static modules
- http_ssl module
- http_realip module
- http_addition module
- http_sub module
- http_gunzip module
- http_gzip_static module
- http_random_index module
- http_secure_link module
- http_stub_status module
- http_auth_request module
- http_slice module

Modules removed: **http_dav**, http_flv, http_mp4

#### Optimizations and changes made

Check `/debian/patches` directly for an actual patches
    
* Server version changed to cloudflare-nginx
* [Dynamic TLS Records patch](https://blog.cloudflare.com/optimizing-tls-over-tcp-to-reduce-latency/)
* ngx_mail module with [xmmp patch](https://github.com/cryptofuture/nginx-hda-bundle/blob/master/debian/patches/) backported from [nginx-xmpp](https://github.com/robn/nginx-xmpp)
* [nginx-cache-purge](https://github.com/xnohat/nginx-cache-purge/raw/master/nginx-cache-purge) script included

### FAQ

#### I want to add my or someone's nginx module to the PPA
*Module should be dynamic!* 
*Fast way #1*: Pull request with changes, better if module will be as git submodule.  Don't forget to change rules file and create install rules for module.  
*Fast way #2*: Contact me, make donation and I would add your module ASAP  
*Slower way: Create issue request with module description and link to module, and I'll do it myself in spare time.  

#### Q: Why you switched from stable to mainline builds?
Nginx mainline builds more stable now, and its easier to receive news about new mainline release, even before source is available on nginx.org from nginx mailing list. Stable nginx versions releases became even less frequent, and a lot fixes not imported in stable version, only critical and secure fixes. Main reason I used stable version before, was lifecycle and modules support. But since most 3-rd party modules are dynamic now, is not crucial even if some module will break.

#### Why no TLSv1.3 support?
Even in bionic (18.04) Ubuntu ships openssl 1.1.0, and I don't want to support openssl in Ubuntu on my own, since it needs critical security updates, which I'll not be able to provide as fast as Canonical security team.
