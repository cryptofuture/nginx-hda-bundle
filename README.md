  > Need some help with nginx-hda-bundle [snap package](https://github.com/cryptofuture/nginx-hda-bundle-snap)!  

# nginx-hda-bundle
##### Nginx HDA Bundle - Dynamic Modules Power 
 ## Dynamic modules 
- [headers-more-nginx](https://github.com/openresty/headers-more-nginx-module)
- [lua-nginx](https://github.com/openresty/lua-nginx-module)
- [naxsi](https://github.com/nbs-system/naxsi) with pull 388 patch (former 258)
- [nginx-length-hiding-filter](https://github.com/nulab/nginx-length-hiding-filter-module)
- [nginx_session_binding_proxy](https://github.com/wburgers/Session-Binding-Proxy)
- [ngx_devel_kit](https://github.com/simpl/ngx_devel_kit)
- [ngx_pagespeed](https://github.com/eustas/ngx_brotli)
- [rds-json-nginx](https://github.com/openresty/rds-json-nginx-module) with pull 4 patch
- [testcookie-nginx](https://github.com/kyprizel/testcookie-nginx-module)
- [nginx-upstream-order](https://github.com/flygoast/ngx_http_upstream_order)
- [ngx_brotli](https://github.com/google/ngx_brotli) :
     - ngx_brotli filter module
     - ngx_brotli static module
- [ngx_postgres module (commumity fork)](https://github.com/konstruxi/ngx_postgres)
- [nchan](https://github.com/slact/nchan)
- [ngx-http-auth-pam](https://github.com/sto/ngx_http_auth_pam_module)
- [echo-nginx-module](https://github.com/openresty/echo-nginx-module)
- [nginx-upstream-fair](https://github.com/gnosek/nginx-upstream-fair)
- [ngx_cache_purge](https://github.com/nginx-modules/ngx_cache_purge)
- [ngx-fancyindex](https://github.com/aperezdc/ngx-fancyindex/)
- [nginx-upload-progress](https://github.com/masterzen/nginx-upload-progress-module)
- [ngx_http_substitutions_filter_module](https://github.com/yaoweibin/ngx_http_substitutions_filter_module)
- [graphite-nginx-module](https://github.com/mailru/graphite-nginx-module/)
- [nginx-module-vts](https://github.com/vozlt/nginx-module-vts)
- [nginx-module-ct](https://github.com/grahamedgecombe/nginx-ct) needs newer openssl versions, possible support on artful and bionic
- [nginx-module-rtmp](https://github.com/sergey-dryabzhinsky/nginx-rtmp-module)
- [nginx-module-ts](https://github.com/arut/nginx-ts-module)
- [nginx-module-sts](https://github.com/vozlt/nginx-module-sts)
- [nginx-module-stream-sts](https://github.com/vozlt/nginx-module-stream-sts)

## Base dynamic modules
- http_xslt module
- http_image_filter module
- http_geoip module
- http_perl module
- ngx_mail module with [xmmp patch](https://github.com/cryptofuture/nginx-hda-bundle/blob/master/debian/patches/) backported from [nginx-xmpp](https://github.com/robn/nginx-xmpp) (linked with mail_ssl)
- ngx_stream module (linked with stream_ssl), and stream_ssl_preread since 1.11.5.
- ngx_http_js module
- ngx_http_mirror_module (build in nginx, since 1.13.4)

## Static modules
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

#### Optimizations made
* Server version changed to cloudflare-nginx
* [Dynamic TLS Records patch](https://blog.cloudflare.com/optimizing-tls-over-tcp-to-reduce-latency/)
* [nginx-cache-purge](https://github.com/xnohat/nginx-cache-purge/raw/master/nginx-cache-purge) script included

#### How-to load dynamic modules?
Add the following to the top of /etc/nginx/nginx.conf (for example after pid) and reload nginx.
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
# You possibly don't need libbrotli for ngx_brotli, dependency removed since nginx 1.11.7, but libbrotli package will be saved in repository
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
  > Note: Use only modules you need to use. With dynamic modules this is pretty easy.
  
#### I want to add my or someone's nginx module to nginx-hda-bundle/ppa.
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
#### Build hacks
Change `buildtype` for Release in ngx_pagespeed config file, to use master version.

#### Q: Why you switched from stable to mainline builds?
Nginx mainline builds more stable now, and its easier to receive news about new mainline release, even before source is available on nginx.org from nginx mailing list. Stable nginx versions releases became even less frequent, and a lot fixes not imported in stable version, only critical and secure fixes. Main reason I used stable version before, was lifecycle and modules support. But since most 3-rd party modules are dynamic now, is not crucial even if some module will break.

#### Donation
Bitcoin : 1N5czHaoSLukFSTq2ZJujaWGjkmBxv2dT9
