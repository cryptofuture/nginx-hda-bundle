# nginx-hda-bundle
#### Modules included 
  1. Dynamic modules
- [headers-more-nginx](https://github.com/openresty/headers-more-nginx-module)
- [lua-nginx](https://github.com/openresty/lua-nginx-module)
- [naxsi](https://github.com/nbs-system/naxsi) with pull 258 patch
- [nginx-length-hiding-filter](https://github.com/nulab/nginx-length-hiding-filter-module)
- [nginx_session_binding_proxy](https://github.com/wburgers/Session-Binding-Proxy)
- [ngx_devel_kit](https://github.com/simpl/ngx_devel_kit)
- [ngx_pagespeed](https://github.com/pagespeed/ngx_pagespeed)
- [rds-json-nginx](https://github.com/openresty/rds-json-nginx-module) with pull 4 patch
- [testcookie-nginx](https://github.com/kyprizel/testcookie-nginx-module)
- [nginx-upstream-order](https://github.com/flygoast/ngx_http_upstream_order)
- [ngx_brotli](https://github.com/google/ngx_brotli) :
     - ngx_brotli filter module
     - ngx_brotli static module
  2. Static modules  
- [ngx_postgres module](https://github.com/FRiCKLE/ngx_postgres) with pull 24 patch

  > Note: I hope it will be dynamic soon too.

  3. Base dynamic modules
- http_xslt module
- http_image_filter module
- http_geoip module
- http_perl module
- ngx_mail module with [xmmp patch](https://github.com/cryptofuture/nginx-hda-bundle/blob/master/debian/patches/xmpp.patch) backported from [nginx-xmpp](https://github.com/robn/nginx-xmpp) (linked with mail_ssl) **NOT FINISHED**
- ngx_stream module (linked with stream_ssl)
- ngx_http_js module 

  >  ngx_https_js upstream version broken now, version from previous package used in ppa.

  4. Static modules
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

Modules removed: http_dav, http_flv, http_mp4

#### Optimizations made
* Server version changed to cloudflare-nginx
* [TLS TTFB optimization](https://www.igvita.com/2013/12/16/optimizing-nginx-tls-time-to-first-byte/)
  > Note: 1360 buffer size used instead 1400.

#### How-to load dynamic modules?
Add the following to the top of /etc/nginx/nginx.conf (for example after pid) and reload nginx.
```bash
load_module modules/ndk_http_module.so;
load_module modules/ngx_http_geoip_module.so;
load_module modules/ngx_http_headers_more_filter_module.so;
load_module modules/ngx_http_image_filter_module.so;
load_module modules/ngx_http_length_hiding_filter_module.so;
load_module modules/ngx_http_lua_module.so;
load_module modules/ngx_http_naxsi_module.so;
load_module modules/ngx_http_njs_filter_module.so;
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
```
  > Note: Use only modules you need to use. With dynamic modules this is pretty easy.
  
#### I want to add my or someone nginx module to nginx-hda-bundle/ppa.
**Module should be dynamic!**  
*Fast-way*: Pull request with changes, better if module will be as git submodule.  Don't forget to change rules file and create install rules for module.  
*Slower way*: Create issue request with module description and link to module, and I'll do it myself in spare time.

#### Where I can find PPA?
PPA located [here](https://launchpad.net/~hda-me/+archive/ubuntu/nginx-stable)
You can add it with
```bash
sudo apt-add-repository ppa:hda-me/nginx-stable
sudo apt-get update
sudo apt-get install nginx nginx-module-name-you-wish
```

#### Donation
Bitcoin : 1N5czHaoSLukFSTq2ZJujaWGjkmBxv2dT9
