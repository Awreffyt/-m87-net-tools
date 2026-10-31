/* © 2026 M87 · 自有手写资产，未经授权禁止复制、转售或二次分发 */
/* 站点身份证：每个站一个独立代号 + 版本号，按域名自动区分。
 *
 * 加一个新站，只要在 hosts 里加一行：
 *   'your-domain.com': { code: 'm87-a', name: 'A站', version: '1.0.0' },
 * 没登记的域名会用 default。
 *
 * 版本号同时用于给脚本去缓存，改完记得把对应站的 version 调一下。
 */
window.M87_SITE = {
  default: { code: 'm87-main', name: 'M87 主站', version: '2.9.0' },
  /* 线上抓取后端：填了就用它（自有 PHP），没填或不可用则自动走公共转发。 */
  backend: 'https://gggg.rf.gd/proxy.php',
  hosts: {
    'awreffyt.github.io': { code: 'm87-main', name: 'M87 主站', version: '2.9.0' },
    localhost: { code: 'm87-local', name: 'M87 本地版', version: '2.9.0' },
    '127.0.0.1': { code: 'm87-local', name: 'M87 本地版', version: '2.9.0' },
  },
  /* 加载顺序不能改：common 先于所有模块，app 最后 */
  files: [
    'common.js',
    'local.obf.js',
    'probe.js',
    'extract.obf.js',
    'dns.js',
    'capture.js',
    'app.js',
    'cipher.obf.js',
  ],
};
