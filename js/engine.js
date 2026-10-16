/* SMS Guard AI — rule engine (ตรรกะตรวจจับเดิม ย้ายมาจาก index.html) */
(function (global) {
    // รายชื่อโดเมนและบริการทางการที่ได้รับการรับรองความปลอดภัยครบทุกระบบ (Trusted Authority Whitelist)
    const officialDomainRegex = /^(?:https?:\/\/)?(?:[a-zA-Z0-9-]+\.)*(true\.th|truemoveh\.com|truemoney\.com|trueid\.net|ttid\.co|truevisionsnow\.com|truecorp\.co\.th|tmn\.app\.link|ss\.true\.th|ais\.th|ais\.co\.th|m\.ais\.co\.th|myais\.ais\.co\.th|dtac\.co\.th|ntplc\.co\.th|mybynt\.com|tot\.co\.th|cattelecom\.com|kbank\.co\.th|kasikornbank\.com|k-plus\.com|scb\.co\.th|scbeasy\.com|scbx\.com|bangkokbank\.com|bualuang\.co\.th|ktb\.co\.th|krungthai\.com|paotang\.com|krungsri\.com|uchouse\.com|krungsriauto\.com|ttbbank\.com|gsb\.or\.th|baac\.or\.th|cimbthai\.com|uob\.co\.th|lhbank\.co\.th|kkpfg\.com|tisco\.co\.th|\.go\.th|dopa\.go\.th|rd\.go\.th|sso\.go\.th|moph\.go\.th|nbtc\.go\.th|royalthaipolice\.go\.th|instagram\.com|ig\.me|cdninstagram\.com|facebook\.com|fb\.me|m\.me|messenger\.com|meta\.com|threads\.net|line\.me|lin\.ee|t\.me|telegram\.org|twitter\.com|x\.com|t\.co|google\.com|g\.co|youtube\.com|youtu\.be|gmail\.com|apple\.com|icloud\.com|microsoft\.com|live\.com|msn\.com|whatsapp\.com|wa\.me|discord\.com|discord\.gg|steampowered\.com|steamcommunity\.com|roblox\.com|openai\.com|chatgpt\.com|shopee\.co\.th|shp\.ee|spx\.co\.th|lazada\.co\.th|s\.lazada\.co\.th|grab\.com|lineman\.line\.me|robinhood\.in\.th|foodpanda\.co\.th|7eleven\.co\.th|cpall\.co\.th|flashexpress\.co\.th|flashexpress\.com|th\.kerryexpress\.com|kerryexpress\.com|kex-express\.com|thailandpost\.co\.th|jtexpress\.co\.th|dhl\.com|dhl\.co\.th|ninjavan\.co|best-inc\.co\.th|pea\.co\.th|mea\.or\.th|mwa\.co\.th|pwa\.co\.th|netflix\.com|hotstar\.com|viu\.com|wetv\.vip|iq\.com|tiktok\.com|vt\.tiktok\.com|spotify\.com)(?:[\/:?]|$)/i;

    function extractUrls(text) {
      const urlRegex = /(?:https?:\/\/)?(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,6}(?:\/[^\s]*)?/gi;
      return text.match(urlRegex) || [];
    }

    function getUntrustedUrls(text) {
      const urls = extractUrls(text);
      return urls.filter(u => !officialDomainRegex.test(u.trim()));
    }

    // รูปแบบคำศัพท์และสแลงเว็บพนันออนไลน์ครบวงจร (Online Gambling, Casino & Slot Slang)
    const gamblingPattern = /สายบา|บาคาร่า|บาครบ|รูเล็ต|ไฮโล|ป๊อกเด้ง|เสือมังกร|\bpg\b|pg\s*slot|พีจี|สล็อต|slot|คาสิโน|casino|แทงบอล|แทงหวย|แทง|ค่าน้ำ|เครดิตฟรี|แจกเครดิต|โบนัส|แตกง่าย|แตกหนัก|แตกจริง|แตกบ่อย|แตกยับ|ไหลรัว|ไหลดี|ปั่นสล็อต|เบท|\bbet\b|หมุนสล็อต|ฟรีสปิน|\bwin\b|กำไรฉ่ำ|กำไรเน้น|บวกหนัก|ยูสใหม่|ยูสเซอร์|เว็บตรง|เว็บใหญ่|เว็บแม่|ค่ายใหญ่|ค่ายตรง|ถอนไม่อั้น|ถอนได้จริง|คืนยอดเสีย|แจกทุน|สูตรสล็อต|ระบบออโต้|ฝาก.*ถอน|ไม่มีขั้นต่ำ|ไม้ใหญ่|ไม้ละ|ไม่ล็อคยูส|ล็อคยูส|เฮง|heng|\b88\b|\b888\b|\b777\b|\b168\b/i;

    // ฐานข้อมูลแอปและบริการทางการครบทุกระบบ (All-System Entity & Intent Knowledge Graph)
    const knownEntities = [
      // 1. ค่ายมือถือและโทรคมนาคม (Telecom Operators)
      {
        id: 'trueid',
        name: 'TrueID / TrueVisions NOW (สตรีมมิ่งความบันเทิง)',
        keywords: /trueid|ทรูไอดี|ttid\.co|now ent|truevisions|สำรับฆาตกร|รับชมซีรีส์/i,
        domains: ['trueid.net', 'ttid.co', 'truevisionsnow.com', 'true.th'],
        category: 'ค่ายมือถือและสตรีมมิ่ง',
        intentGeneral: 'แนะนำซีรีส์/ภาพยนตร์ และสมัครแพ็กเกจความบันเทิง TrueID NOW'
      },
      {
        id: 'true',
        name: 'True / TrueMove H / TrueMoney',
        keywords: /ทรู|true|truemove|truemoney|tmn|แพ็กเกจ.*เน็ต|\*900\*/i,
        domains: ['true.th', 'truemoveh.com', 'truemoney.com', 'tmn.app.link', 'ss.true.th', 'truecorp.co.th'],
        category: 'ค่ายมือถือและการเงิน',
        intentOtp: 'ส่งรหัส OTP ยืนยันการทำรายการ TrueMoney',
        intentGeneral: 'แจ้งแพ็กเกจเน็ตและบริการทางการของเครือข่าย True'
      },
      {
        id: 'ais',
        name: 'AIS / myAIS (ผู้ให้บริการเครือข่ายมือถือ)',
        keywords: /ais|เอไอเอส|\*777\*|myais/i,
        domains: ['ais.th', 'ais.co.th', 'm.ais.co.th', 'myais.ais.co.th'],
        category: 'ค่ายมือถือ',
        intentOtp: 'ส่งรหัส OTP บริการ myAIS',
        intentGeneral: 'แจ้งแพ็กเกจและบริการทางการของเครือข่าย AIS'
      },
      {
        id: 'dtac',
        name: 'Dtac (ผู้ให้บริการเครือข่ายมือถือ)',
        keywords: /dtac|ดีแทค|\*104\*/i,
        domains: ['dtac.co.th'],
        category: 'ค่ายมือถือ',
        intentOtp: 'ส่งรหัส OTP บริการ dtac app',
        intentGeneral: 'แจ้งแพ็กเกจและบริการทางการของเครือข่าย Dtac'
      },
      {
        id: 'nt',
        name: 'NT (โทรคมนาคมแห่งชาติ - TOT / CAT)',
        keywords: /ntplc|mybynt|tot|cat/i,
        domains: ['ntplc.co.th', 'mybynt.com', 'tot.co.th', 'cattelecom.com'],
        category: 'ค่ายมือถือและเน็ตบ้าน',
        intentGeneral: 'แจ้งบริการและแพ็กเกจอินเทอร์เน็ต NT'
      },

      // 2. ธนาคารและสถาบันการเงิน (Banks & FinTech)
      {
        id: 'kbank',
        name: 'ธนาคารกสิกรไทย (KBank)',
        keywords: /กสิกร|kbank|kasikorn|k-plus/i,
        domains: ['kasikornbank.com', 'kbank.co.th', 'k-plus.com'],
        category: 'ธนาคารและการเงิน',
        intentOtp: 'ส่งรหัส OTP ธุรกรรมธนาคารกสิกรไทย',
        intentGeneral: 'แจ้งข้อมูลบริการทางการเงิน / บัญชีธนาคารกสิกรไทย'
      },
      {
        id: 'scb',
        name: 'ธนาคารไทยพาณิชย์ (SCB)',
        keywords: /ไทยพาณิชย์|scb|scbeasy/i,
        domains: ['scb.co.th', 'scbeasy.com', 'scbx.com'],
        category: 'ธนาคารและการเงิน',
        intentOtp: 'ส่งรหัส OTP ธุรกรรมธนาคารไทยพาณิชย์',
        intentGeneral: 'แจ้งข้อมูลบริการทางการเงิน / บัญชีธนาคารไทยพาณิชย์'
      },
      {
        id: 'ktb',
        name: 'ธนาคารกรุงไทย (Krungthai / เป๋าตัง)',
        keywords: /กรุงไทย|ktb|เป๋าตัง/i,
        domains: ['krungthai.com', 'ktb.co.th', 'paotang.com'],
        category: 'ธนาคารและการเงิน',
        intentOtp: 'ส่งรหัส OTP แอป Krungthai NEXT / เป๋าตัง',
        intentGeneral: 'แจ้งข้อมูลบริการทางการเงิน / สิทธิประโยชน์รัฐ'
      },
      {
        id: 'bbl',
        name: 'ธนาคารกรุงเทพ (Bangkok Bank)',
        keywords: /กรุงเทพ|bbl|bangkokbank|bualuang/i,
        domains: ['bangkokbank.com', 'bualuang.co.th'],
        category: 'ธนาคารและการเงิน',
        intentOtp: 'ส่งรหัส OTP ธนาคารกรุงเทพ',
        intentGeneral: 'แจ้งข้อมูลบริการทางการเงินธนาคารกรุงเทพ'
      },
      {
        id: 'ttb',
        name: 'ธนาคารทหารไทยธนชาต (TTB)',
        keywords: /ttb|ทหารไทยธนชาต/i,
        domains: ['ttbbank.com'],
        category: 'ธนาคารและการเงิน',
        intentOtp: 'ส่งรหัส OTP บริการ ttb touch',
        intentGeneral: 'แจ้งข้อมูลบริการทางการเงินธนาคาร TTB'
      },
      {
        id: 'krungsri',
        name: 'ธนาคารกรุงศรีอยุธยา (Krungsri / UCHOOSE)',
        keywords: /กรุงศรี|krungsri|uchouse/i,
        domains: ['krungsri.com', 'uchouse.com', 'krungsriauto.com'],
        category: 'ธนาคารและการเงิน',
        intentOtp: 'ส่งรหัส OTP ธนาคารกรุงศรีอยุธยา',
        intentGeneral: 'แจ้งข้อมูลบริการทางการเงินธนาคารกรุงศรี'
      },
      {
        id: 'gsb',
        name: 'ธนาคารออมสิน (GSB / MyMo)',
        keywords: /ออมสิน|gsb|mymo/i,
        domains: ['gsb.or.th'],
        category: 'ธนาคารและการเงิน',
        intentOtp: 'ส่งรหัส OTP แอป MyMo ธนาคารออมสิน',
        intentGeneral: 'แจ้งข้อมูลบริการทางการเงินธนาคารออมสิน'
      },
      {
        id: 'baac',
        name: 'ธ.ก.ส. (BAAC / A-Mobile)',
        keywords: /ธ\.ก\.ส\.|baac/i,
        domains: ['baac.or.th'],
        category: 'ธนาคารและการเงิน',
        intentOtp: 'ส่งรหัส OTP แอป BAAC A-Mobile',
        intentGeneral: 'แจ้งข้อมูลบริการทางการเงิน ธ.ก.ส.'
      },

      // 3. โลจิสติกส์และการขนส่ง (Logistics & Couriers)
      {
        id: 'flash',
        name: 'Flash Express (บริษัทขนส่งพัสดุ)',
        keywords: /flash|แฟลช/i,
        domains: ['flashexpress.co.th', 'flashexpress.com'],
        category: 'ขนส่งพัสดุ',
        intentGeneral: 'แจ้งสถานะการจัดส่งพัสดุ Flash Express'
      },
      {
        id: 'kerry',
        name: 'Kerry Express / KEX (บริษัทขนส่งพัสดุ)',
        keywords: /kerry|เคอรี่|kex/i,
        domains: ['th.kerryexpress.com', 'kerryexpress.com', 'kex-express.com'],
        category: 'ขนส่งพัสดุ',
        intentGeneral: 'แจ้งสถานะการจัดส่งพัสดุ Kerry Express / KEX'
      },
      {
        id: 'thpost',
        name: 'ไปรษณีย์ไทย (Thailand Post)',
        keywords: /ไปรษณีย์ไทย|thailandpost/i,
        domains: ['thailandpost.co.th'],
        category: 'ขนส่งพัสดุ',
        intentGeneral: 'แจ้งสถานะพัสดุไปรษณีย์ไทย'
      },
      {
        id: 'jtexpress',
        name: 'J&T Express',
        keywords: /j&t|เจแอนด์ที/i,
        domains: ['jtexpress.co.th'],
        category: 'ขนส่งพัสดุ',
        intentGeneral: 'แจ้งสถานะการจัดส่งพัสดุ J&T Express'
      },

      // 4. โซเชียลมีเดียและแพลตฟอร์มระดับโลก (Social Media & Global Tech)
      {
        id: 'instagram',
        name: 'Instagram (แอปโซเชียลมีเดียในเครือ Meta)',
        keywords: /instagram|อินสตาแกรม|\big\b|ig\.me/i,
        domains: ['instagram.com', 'ig.me', 'cdninstagram.com'],
        category: 'โซเชียลมีเดีย',
        intentOtp: 'ส่งรหัสยืนยันตัวตนหรือรีเซ็ตรหัสผ่าน Instagram',
        intentGeneral: 'การใช้งานและบริการของ Instagram'
      },
      {
        id: 'facebook',
        name: 'Facebook / Meta / Messenger',
        keywords: /facebook|เฟซบุ๊ก|เฟสบุ๊ก|\bfb\b|fb\.me|messenger|meta/i,
        domains: ['facebook.com', 'fb.me', 'm.me', 'messenger.com', 'meta.com', 'threads.net'],
        category: 'โซเชียลมีเดีย',
        intentOtp: 'ส่งรหัสยืนยันตัวตนหรือรีเซ็ตรหัสผ่าน Facebook',
        intentGeneral: 'การใช้งานและบริการของ Facebook / Meta'
      },
      {
        id: 'line',
        name: 'LINE (แอปแชทและสื่อสารทางการ)',
        keywords: /line\s*security|line\s*pay|รหัสยืนยัน.*line|line\s*verification|line\s*official|line\s*corp|lin\.ee/i,
        domains: ['line.me', 'lin.ee'],
        category: 'โซเชียลมีเดีย',
        intentOtp: 'ส่งรหัสยืนยันบัญชี LINE หรือ LINE Pay',
        intentGeneral: 'การติดต่อสื่อสารและบริการทางการของ LINE'
      },
      {
        id: 'tiktok',
        name: 'TikTok (แอปวิดีโอสั้น)',
        keywords: /tiktok|ติ๊กต็อก|ติ๊กตอก/i,
        domains: ['tiktok.com', 'vt.tiktok.com'],
        category: 'โซเชียลมีเดีย',
        intentOtp: 'ส่งรหัสยืนยันตัวตนบัญชี TikTok',
        intentGeneral: 'การใช้งานและบริการของ TikTok'
      },
      {
        id: 'twitter',
        name: 'X / Twitter (แพลตฟอร์มโซเชียลมีเดีย)',
        keywords: /twitter|ทวิตเตอร์|\bx\.com\b|\bt\.co\b/i,
        domains: ['x.com', 'twitter.com', 't.co'],
        category: 'โซเชียลมีเดีย',
        intentOtp: 'ส่งรหัสยืนยันตัวตนบัญชี X / Twitter',
        intentGeneral: 'การใช้งานและบริการของ X / Twitter'
      },
      {
        id: 'telegram',
        name: 'Telegram (แอปส่งข้อความสากล)',
        keywords: /telegram|t\.me/i,
        domains: ['t.me', 'telegram.org'],
        category: 'โซเชียลมีเดีย',
        intentOtp: 'ส่งรหัสยืนยันตัวตนเข้าสู่ระบบ (Login / 2FA Code)',
        intentGeneral: 'การติดต่อสื่อสารผ่าน Telegram'
      },
      {
        id: 'google',
        name: 'Google / YouTube',
        keywords: /\bgoogle\b|\byoutube\b|g-[0-9]{4,8}/i,
        domains: ['google.com', 'g.co', 'youtube.com', 'youtu.be', 'gmail.com'],
        category: 'บริการระดับโลก',
        intentOtp: 'ส่งรหัสยืนยันตัวตนบัญชี Google (2FA)',
        intentGeneral: 'แจ้งเตือนความปลอดภัยบัญชี Google'
      },
      {
        id: 'apple',
        name: 'Apple / iCloud',
        keywords: /\bapple\b|\bicloud\b|appleid/i,
        domains: ['apple.com', 'icloud.com'],
        category: 'บริการระดับโลก',
        intentOtp: 'ส่งรหัสความปลอดภัย Apple ID / Two-Factor Code',
        intentGeneral: 'แจ้งเตือนบัญชี Apple ID'
      },

      // 5. หน่วยงานภาครัฐและสาธารณูปโภค (Government & Public Utilities)
      {
        id: 'electric',
        name: 'การไฟฟ้านครหลวง / ภูมิภาค (MEA / PEA)',
        keywords: /การไฟฟ้า|กฟภ|กฟน|pea|mea|มิเตอร์ไฟ/i,
        domains: ['pea.co.th', 'mea.or.th'],
        category: 'สาธารณูปโภค',
        intentGeneral: 'แจ้งค่าไฟฟ้า / คืนเงินประกันการใช้มิเตอร์ไฟ'
      },
      {
        id: 'water',
        name: 'การประปานครหลวง / ภูมิภาค (MWA / PWA)',
        keywords: /การประปา|กปน|กปภ|mwa|pwa/i,
        domains: ['mwa.co.th', 'pwa.co.th'],
        category: 'สาธารณูปโภค',
        intentGeneral: 'แจ้งค่าน้ำประปาและบริการสาธารณูปโภค'
      },
      {
        id: 'gov',
        name: 'หน่วยงานราชการไทย (Thai Government)',
        keywords: /สรรพากร|ประกันสังคม|\bsso\b|ดีเอสไอ|\bdsi\b|กสทช|หมายศาล|สภ\.|thaid/i,
        domains: ['.go.th', 'rd.go.th', 'sso.go.th', 'dopa.go.th'],
        category: 'หน่วยงานราชการ',
        intentGeneral: 'การแจ้งข้อมูลหรือบริการทางการของหน่วยงานรัฐ'
      },

      // 6. อีคอมเมิร์ซ (E-Commerce)
      {
        id: 'shopee',
        name: 'Shopee (ช้อปปี้)',
        keywords: /shopee|ช้อปปี้|shp\.ee/i,
        domains: ['shopee.co.th', 'shp.ee', 'spx.co.th'],
        category: 'อีคอมเมิร์ซ',
        intentGeneral: 'แจ้งสถานะคำสั่งซื้อหรือสิทธิประโยชน์ Shopee'
      },
      {
        id: 'lazada',
        name: 'Lazada (ลาซาด้า)',
        keywords: /lazada|ลาซาด้า/i,
        domains: ['lazada.co.th', 's.lazada.co.th'],
        category: 'อีคอมเมิร์ซ',
        intentGeneral: 'แจ้งสถานะคำสั่งซื้อหรือสิทธิประโยชน์ Lazada'
      },

      // 7. โรงพยาบาลและสาธารณสุข (Hospitals & Healthcare)
      {
        id: 'hospital',
        name: 'โรงพยาบาล / สถานพยาบาลทางการ',
        keywords: /โรงพยาบาล|รพ\.|หมอพร้อม|ศิริราช|จุฬาลงกรณ์|รามาธิบดี/i,
        domains: ['moph.go.th'],
        category: 'สถานพยาบาล',
        intentGeneral: 'แจ้งเตือนนัดหมายพบแพทย์และคำแนะนำการเตรียมตัว'
      },

      // 8. กลุ่มมิจฉาชีพและเว็บพนัน (Scam & Blacklist)
      {
        id: 'gambling',
        name: 'เว็บพนันออนไลน์ / สล็อต / บาคาร่า',
        keywords: gamblingPattern,
        domains: [],
        category: 'เว็บผิดกฎหมาย',
        intentGeneral: 'ชักชวนเล่นการพนันออนไลน์ผิดกฎหมาย (พรบ.การพนัน)'
      },
      {
        id: 'loan',
        name: 'แก๊งเงินกู้นอกระบบ / มิจฉาชีพสินเชื่อ',
        keywords: /กู้|สินเชื่อ|เงินด่วน|ไม่เช็คบูโร|อนุมัติไว/i,
        domains: [],
        category: 'มิจฉาชีพเงินกู้',
        intentGeneral: 'หลอกลวงให้กู้เงินด่วนนอกระบบ / หลอกโอนเงินค่ามัดจำ'
      },
      {
        id: 'job',
        name: 'มิจฉาชีพหลอกทำงานออนไลน์',
        keywords: /งานออนไลน์|กดยืนยันออเดอร์|โปรโมทสินค้า|วันละ.*บาท/i,
        domains: [],
        category: 'มิจฉาชีพทำงานเสริม',
        intentGeneral: 'หลอกทำงานเสริมรายได้สูงเพื่อล่อลวงโอนเงิน'
      }
    ];

    function determineIntent(text, entity) {
      if (entity && entity.id === 'gambling') {
        return 'ชักชวนเล่นการพนันออนไลน์ผิดกฎหมาย (สล็อต / บาคาร่า)';
      }
      if (/ระงับ|อายัด|ถูกล็อก|เข้าสู่ระบบ.*ด่วน|มีผู้พยายามเข้าสู่ระบบ/i.test(text)) {
        return 'แจ้งเตือนบัญชีถูกระงับ/มีความผิดปกติ เพื่อข่มขู่ให้กรอกรหัสผ่าน';
      }
      if (/พัสดุ.*(ตกค้าง|ระงับ|ยืนยัน|ชำระ)/i.test(text)) {
        return 'แจ้งพัสดุตกค้างและเร่งให้ยืนยันที่อยู่ / ชำระค่าธรรมเนียมจัดส่ง';
      }
      if (/กู้|สินเชื่อ|เงินด่วน/i.test(text)) {
        return 'ชักชวนกู้เงินด่วนนอกระบบ / หลอกให้ทำสัญญาเงินกู้';
      }
      if (/คืนเงินประกัน|คืนภาษี|มิเตอร์ไฟ/i.test(text)) {
        return 'แอบอ้างคืนเงินประกันมิเตอร์ไฟฟ้า / ภาษี เพื่อหลอกติดตั้งแอปดูดเงิน';
      }
      if (/code|otp|verification|รหัสยืนยัน/i.test(text)) {
        return entity && entity.intentOtp ? entity.intentOtp : (entity ? `ส่งรหัสยืนยันตัวตนความปลอดภัย ${entity.name} (OTP / 2FA)` : 'ส่งรหัสยืนยันตัวตนความปลอดภัย (OTP / 2FA)');
      }
      if (/รีเซ็ตรหัสผ่าน|reset.*password|เปลี่ยนรหัสผ่าน|แตะเพื่อรีเซ็ต/i.test(text)) {
        return entity ? `ขอรีเซ็ตรหัสผ่านบัญชี ${entity.name} (Password Reset Request)` : 'ส่งลิงก์รีเซ็ตรหัสผ่านบัญชีตามคำขอของผู้ใช้ (Password Reset)';
      }
      if (/ซีรีส์|ภาพยนตร์|รับชม|ละคร|สตรีมมิ่ง|ดูเลย/i.test(text)) {
        return 'แนะนำคอนเทนต์ซีรีส์/ภาพยนตร์ และบริการสตรีมมิ่งความบันเทิงทางการ';
      }
      if (/แพ็กเกจ|เน็ต|gb|mbps|\*\d{3}\*/i.test(text)) {
        return 'แจ้งรายละเอียดแพ็กเกจเน็ตและบริการเครือข่ายมือถือ';
      }
      if (/เงินเข้าบัญชี|โอนเงินสำเร็จ|ยอดเงินคงเหลือ/i.test(text)) {
        return 'การแจ้งเตือนธุรกรรมทางการเงินตามปกติของธนาคาร (เงินเข้า/เงินออก)';
      }
      if (/รพ\.|โรงพยาบาล|นัดหมายพบแพทย์|งดน้ำงดอาหาร/i.test(text)) {
        return 'แจ้งเตือนนัดหมายพบแพทย์และคำแนะนำการเตรียมตัวจากสถานพยาบาล';
      }
      return entity && entity.intentGeneral ? entity.intentGeneral : 'แจ้งข้อมูลหรือการสนทนาทั่วไป';
    }

    // ระบบประเมิน 3 ลำดับชั้นตามมาตรฐาน (Strict 3-Tier Hierarchy)
    // 1. ลิงก์ก่อนเสมอ (Tier 1) -> 2. ชื่อแอปในข้อความ (Tier 2) -> 3. จัดการเมื่อไม่มีชื่อแอป (Tier 3)
    function analyzeMessageHierarchy(text) {
      const urls = extractUrls(text);
      let appName = '';
      let appCategory = '';
      let intent = '';
      let linkAnalysis = {
        status: 'neutral',
        isMismatch: false,
        text: 'ℹ️ ข้อความนี้ไม่มีลิงก์แนบมา ปลอดภัยจากการถูกดูดข้อมูลผ่านเว็บ'
      };
      let hierarchyTier = '';
      let hierarchyTierBadge = '';

      // ==============================================================
      // TIER 1: อันดับแรก ถ้ามีลิงก์ ให้กดเข้าไปดูที่ลิงก์ก่อนว่ามาจากแอปอะไร
      // ==============================================================
      if (urls.length > 0) {
        hierarchyTier = 'ลำดับที่ 1: ตรวจสอบจากลิงก์แนบ (Link-First Inspection)';
        hierarchyTierBadge = '🔗 ลำดับที่ 1 (ตรวจจากลิงก์)';
        const rawUrl = urls[0].toLowerCase();

        // 1.1 ตรวจสอบว่าลิงก์หรือข้อความเป็นเว็บพนันผิดกฎหมายหรือไม่
        if (gamblingPattern.test(text) || gamblingPattern.test(rawUrl)) {
          appName = 'เว็บพนันออนไลน์ / สล็อต / คาสิโนผิดกฎหมาย';
          appCategory = 'เว็บพนันผิดกฎหมาย';
          intent = 'ชักชวนเล่นการพนันออนไลน์ผิดกฎหมาย (สล็อต / บาคาร่า)';
          linkAnalysis = {
            status: 'danger',
            isMismatch: true,
            text: `🚨 ลิงก์อันตราย (${urls[0]}) เชื่อมโยงไปยังเว็บไซต์พนันออนไลน์ผิดกฎหมาย ห้ามคลิกเด็ดขาด`
          };
          return { appName, appCategory, intent, linkAnalysis, hierarchyTier, hierarchyTierBadge, isGambling: true };
        }

        // 1.2 ตรวจสอบว่าโดเมนในลิงก์เป็นของแอปทางการตัวใดในฐานข้อมูล
        let domainOwnerEntity = null;
        for (const ent of knownEntities) {
          if (ent.domains && ent.domains.length > 0) {
            if (ent.domains.some(d => rawUrl.includes(d.toLowerCase()))) {
              domainOwnerEntity = ent;
              break;
            }
          }
        }

        // 1.3 ตรวจสอบว่าในข้อความมีการกล่าวอ้างถึงแอป/หน่วยงานใดหรือไม่
        let claimedEntity = null;
        for (const ent of knownEntities) {
          if (ent.id !== 'gambling' && ent.keywords && ent.keywords.test(text)) {
            claimedEntity = ent;
            break;
          }
        }

        if (domainOwnerEntity) {
          // ลิงก์มาจากแอปทางการที่ได้รับการรับรอง
          appName = domainOwnerEntity.name;
          appCategory = domainOwnerEntity.category || 'บริการทางการ';
          intent = determineIntent(text, domainOwnerEntity);
          linkAnalysis = {
            status: 'safe',
            isMismatch: false,
            text: `✅ ลิงก์ตรงกับแอปจริง (${urls[0]} เป็นโดเมนทางการของ ${domainOwnerEntity.name})`
          };
          return { appName, appCategory, intent, linkAnalysis, hierarchyTier, hierarchyTierBadge, matchedEntity: domainOwnerEntity };
        } else {
          // ลิงก์ไม่ใช่โดเมนทางการ
          if (claimedEntity) {
            // แอบอ้างแอป/หน่วยงานแต่ใช้ลิงก์อื่น (Domain Mismatch Phishing)
            appName = `${claimedEntity.name} (ตรวจพบการแอบอ้าง)`;
            appCategory = 'มิจฉาชีพแอบอ้างหน่วยงาน';
            intent = `แอบอ้างชื่อ "${claimedEntity.name}" เพื่อหลอกให้คลิกลิงก์แปลกปลอม`;
            linkAnalysis = {
              status: 'danger',
              isMismatch: true,
              text: `🚨 ลิงก์ไม่ตรงกับแอปจริง! (Domain Mismatch) แอบอ้างชื่อ "${claimedEntity.name}" แต่ใช้ลิงก์แปลกปลอม (${urls[0]}) ซึ่งไม่ใช่โดเมนทางการ เข้าข่าย Phishing ดักขโมยข้อมูลหรือดูดเงิน 100%`
            };
            return { appName, appCategory, intent, linkAnalysis, hierarchyTier, hierarchyTierBadge, matchedEntity: claimedEntity, isMismatch: true };
          } else {
            // ลิงก์ภายนอกที่ไม่ระบุแอป
            appName = 'เว็บไซต์ภายนอกที่ไม่ระบุแอปทางการ';
            appCategory = 'ลิงก์ภายนอกต้องสงสัย';
            intent = 'ล่อลวงให้คลิกเปิดเว็บไซต์ภายนอกที่ไม่ผ่านการรับรองความปลอดภัย';
            linkAnalysis = {
              status: 'danger',
              isMismatch: true,
              text: `⚠️ พบลิงก์ภายนอกต้องสงสัย (${urls[0]}) ที่ไม่ได้รับการรับรองความปลอดภัย เสี่ยงเป็นเว็บ Phishing หรือมัลแวร์`
            };
            return { appName, appCategory, intent, linkAnalysis, hierarchyTier, hierarchyTierBadge, isUntrustedLink: true };
          }
        }
      }

      // ==============================================================
      // TIER 2: ถ้าไม่มีลิงก์ ให้ดูจากข้อความว่ามีชื่อแอปโผล่มาไหม
      // ==============================================================
      hierarchyTier = 'ลำดับที่ 2: สกัดชื่อแอปจากข้อความ (Text-Based App Identification)';
      hierarchyTierBadge = '📱 ลำดับที่ 2 (ตรวจจากชื่อแอป)';
      let textEntity = null;

      // 2.1 ตรวจสอบชื่อแอปจากฐานข้อมูล knownEntities (ไม่รวมกลุ่มมิจฉาชีพ)
      for (const ent of knownEntities) {
        if (ent.id !== 'gambling' && ent.id !== 'loan' && ent.id !== 'job' && ent.keywords && ent.keywords.test(text)) {
          textEntity = ent;
          break;
        }
      }

      // 2.2 Dynamic Brand/App Extraction สกัดชื่อแอปแบบไดนามิกหากไม่มีในฐานข้อมูล
      if (!textEntity) {
        const brandRegex = /(?:จากแอป|ผ่านแอป|แอปพลิเคชัน|แอป|บริการของ)\s*([A-Za-z0-9ก-๙]{2,15})/;
        const match = text.match(brandRegex);
        if (match) {
          const extracted = match[1].trim();
          if (extracted.length >= 2 && !/^(คุณ|ท่าน|เพื่อ|ด่วน|นี้|นั้น|ข้อความ|ระบบ|รหัส|การ|และ|หรือ|ของ|ใน|มี|จะ|ได้)$/i.test(extracted)) {
            textEntity = {
              id: 'extracted_' + extracted.toLowerCase(),
              name: `${extracted} (ระบุในข้อความ)`,
              category: 'แอป/บริการที่ระบุในข้อความ',
              intentGeneral: `การแจ้งเตือนหรือบริการจาก ${extracted}`
            };
          }
        }
      }

      if (textEntity) {
        appName = textEntity.name;
        appCategory = textEntity.category || 'บริการ/แอปพลิเคชัน';
        intent = determineIntent(text, textEntity);
        linkAnalysis = {
          status: 'safe',
          isMismatch: false,
          text: 'ℹ️ ข้อความนี้ไม่มีลิงก์แนบมา ปลอดภัยจากการถูกหลอกให้คลิกดูดข้อมูลผ่านหน้าเว็บ'
        };
        return { appName, appCategory, intent, linkAnalysis, hierarchyTier, hierarchyTierBadge, matchedEntity: textEntity };
      }

      // ==============================================================
      // TIER 3: แต่ถ้าไม่มีชื่อแอป นายก็ต้องหาวิธีจัดการตรงนี้ให้ได้
      // วิเคราะห์พฤติกรรมและความตั้งใจของข้อความนิรนาม (Zero-App Anonymous Behavioral Profiling)
      // ==============================================================
      hierarchyTier = 'ลำดับที่ 3: จัดการเมื่อไม่มีชื่อแอป (Anonymous Behavioral Profiling)';
      hierarchyTierBadge = '👤 ลำดับที่ 3 (จัดการไร้ชื่อแอป)';

      // 3.1 ตรวจจับพฤติกรรมข่มขู่สร้างความกลัว (Threat / Extortion)
      if (/หมายศาล|คดีความ|ดำเนินคดี|อายัด|กระทำความผิด|ดีเอสไอ|\bdsi\b|สภ\.|ตำรวจ|ถูกระงับ|ปิดกั้นบัญชี/i.test(text)) {
        appName = '⚠️ ไม่ระบุชื่อแอป (ตรวจพบพฤติกรรมข่มขู่สร้างความกลัว)';
        appCategory = 'ข้อความข่มขู่นิรนาม';
        intent = 'สร้างความตื่นตระหนกและข่มขู่ให้เหยื่อกลัว เพื่อหลอกให้ติดต่อกลับหรือโอนเงินเคลียร์คดี';
        linkAnalysis = {
          status: 'warning',
          isMismatch: false,
          text: '⚠️ แม้ไม่มีลิงก์แนบมา แต่มีพฤติกรรมข่มขู่ผิดปกติ ห้ามหลงเชื่อหรือติดต่อกลับเด็ดขาด'
        };
        return { appName, appCategory, intent, linkAnalysis, hierarchyTier, hierarchyTierBadge, isAnonymousThreat: true };
      }

      // 3.2 ตรวจจับพฤติกรรมล่อลวงผลประโยชน์ / เงินกู้นอกระบบ (Bait / Loan Shark)
      if (/กู้|สินเชื่อ|เงินด่วน|อนุมัติวงเงิน|ดอกเบี้ย.*0%|ทำงานออนไลน์|กดออเดอร์|วันละ.*บาท|รับรางวัล|แจกทอง/i.test(text)) {
        appName = '⚠️ ไม่ระบุชื่อแอป (ตรวจพบพฤติกรรมล่อลวงผลประโยชน์/เงินกู้)';
        appCategory = 'มิจฉาชีพล่อลวงการเงินนิรนาม';
        intent = 'ล่อลวงด้วยผลประโยชน์หรือเงินกู้ด่วน เพื่อหลอกให้แอดไลน์หรือโอนเงินค่ามัดจำ';
        linkAnalysis = {
          status: 'warning',
          isMismatch: false,
          text: '⚠️ แม้ไม่มีลิงก์แนบมา แต่มีการเสนอผลประโยชน์เกินจริง ห้ามติดต่อหรือให้ข้อมูลส่วนตัว'
        };
        return { appName, appCategory, intent, linkAnalysis, hierarchyTier, hierarchyTierBadge, isAnonymousBait: true };
      }

      // 3.3 ตรวจจับบทสนทนาในชีวิตประจำวัน / ครอบครัว / บุคคล (Personal Conversation)
      if (/แม่|พ่อ|พี่|น้อง|ลูก|ยาย|ตา|เพื่อน|หนู|ผม|จ๋า|จ๊ะ|ครับ|ค่ะ|กินข้าว|ถึงบ้าน|เลิกงาน|เปิดแอร์|ซื้อกับข้าว|คิดถึง|รัก|อยู่ไหน|นอนหรือยัง|โอเค|ได้เลย|พรุ่งนี้/i.test(text)) {
        appName = '💬 ข้อความส่วนบุคคล (Personal Conversation)';
        appCategory = 'บทสนทนาในชีวิตประจำวัน';
        intent = 'การพูดคุยสนทนาระหว่างบุคคลหรือคนในครอบครัวตามปกติ';
        linkAnalysis = {
          status: 'safe',
          isMismatch: false,
          text: '✅ เป็นบทสนทนาส่วนบุคคล ไม่มีลิงก์และไม่มีพฤติกรรมหลอกลวง ปลอดภัย 100%'
        };
        return { appName, appCategory, intent, linkAnalysis, hierarchyTier, hierarchyTierBadge, isBenignConversation: true };
      }

      // 3.4 ข้อความทั่วไป (Neutral / Unidentified)
      appName = 'ℹ️ ข้อความทั่วไป (ไม่ระบุองค์กร)';
      appCategory = 'ข้อความทั่วไป';
      intent = 'การแจ้งข้อมูลหรือข้อความสื่อสารทั่วไป';
      linkAnalysis = {
        status: 'neutral',
        isMismatch: false,
        text: 'ℹ️ ข้อความไม่มีลิงก์แนบมา ไม่พบความเสี่ยงด้านเว็บ Phishing'
      };
      return { appName, appCategory, intent, linkAnalysis, hierarchyTier, hierarchyTierBadge, isNeutral: true };
    }

    function analyzeMessageContext(text) {
      return analyzeMessageHierarchy(text);
    }

    // ฐานข้อมูลคำและรูปแบบมิจฉาชีพและเว็บพนันออนไลน์ (NLP Pattern Engine)
    const scamRules = [
      // 1. ลิงก์ภายนอก หรือลิงก์ย่อต้องสงสัยที่ไม่ใช่เว็บไซต์ทางการ (Phishing & Suspicious External Links)
      { 
        check: (text) => {
          const untrusted = getUntrustedUrls(text);
          if (untrusted.length > 0) {
            return {
              match: true,
              reason: "พบลิงก์ภายนอก/ลิงก์ย่อต้องสงสัยที่ไม่ใช่เว็บไซต์ทางการ (" + untrusted.slice(0, 2).join(', ') + ") ซึ่ง กสทช. และตำรวจไซเบอร์เตือนว่าห้ามคลิกเด็ดขาด"
            };
          }
          return { match: false };
        },
        score: 45
      },
      // 2. เว็บพนันออนไลน์ / สล็อต / บาคาร่า / คาสิโน / หวย / บอล
      { 
        pattern: gamblingPattern, 
        score: 80, 
        reason: "พบคำศัพท์ชักชวนเล่นการพนันออนไลน์ / บาคาร่า / สล็อตเว็บตรง (สายบา, ไม้ใหญ่, เว็บใหญ่, HENG, เครดิตฟรี) ผิดกฎหมาย พรบ.การพนัน 100%" 
      },
      // 3. หลอกล่อเรื่องพัสดุตกค้าง / บริษัทขนส่ง
      { 
        pattern: /(พัสดุ.*(ตกค้าง|ระงับ|เสียหาย|ชำระค่าจัดส่ง|นำจ่ายไม่ได้|ยืนยันที่อยู่))|(flash|kerry|j&t|ไปรษณีย์ไทย).*(พัสดุ|ส่งของ|พัสดุของท่าน)/i, 
        score: 40, 
        reason: "แอบอ้างบริษัทขนส่ง (Flash, Kerry, ไปรษณีย์ไทย) แจ้งพัสดุตกค้างเพื่อหลอกให้คลิกลิงก์ยืนยัน" 
      },
      // 4. สินเชื่อออนไลน์ / เงินกู้ด่วนนอกระบบ
      { 
        pattern: /กู้|สินเชื่อ|อนุมัติไว|ไม่เช็คบูโร|ผ่อนสบาย|เงินด่วน|โอนไว|อนุมัติแล้ว.*บาท|วงเงินคงเหลือ|รับเงินทันที/i, 
        score: 40, 
        reason: "มีข้อความล่อลวงเรื่องเงินกู้ด่วน หรือสินเชื่อออนไลน์นอกระบบ" 
      },
      // 5. แอบอ้างหน่วยงานรัฐ / การไฟฟ้า / สรรพากร / คืนเงิน
      { 
        pattern: /การไฟฟ้า|กฟภ|กฟน|คืนเงินประกัน|มิเตอร์ไฟ|คืนภาษี|สรรพากร|กสทช|เยียวยา|กระทรวง|หมายศาล|ดีเอสไอ|\bdsi\b|สภ\./i, 
        score: 40, 
        reason: "แอบอ้างหน่วยงานรัฐ (การไฟฟ้า, สรรพากร, กสทช.) เรื่องคืนเงินหรือกระทำความผิดเพื่อหลอกติดตั้งแอปดูดเงิน" 
      },
      // 6. แอบอ้างธนาคาร / บัญชีถูกระงับ
      { 
        pattern: /บัญชี.*(ถูกระงับ|ปิดกั้น|เข้าสู่ระบบ|ยืนยันตัวตน|แฮก|อายัด|ถูกล็อก)|kbank|scb|bbl|ktb.*(ระงับ|ยืนยัน)/i, 
        score: 35, 
        reason: "สร้างความตื่นตระหนก แอบอ้างธนาคารแจ้งว่าบัญชีถูกระงับ เพื่อหลอกขอรหัสผ่านหรือข้อมูลส่วนตัว" 
      },
      // 7. หลอกทำงานเสริมออนไลน์
      { 
        pattern: /งานออนไลน์|กดยืนยันออเดอร์|โปรโมทสินค้า|วันละ.*บาท|ทำงานที่บ้าน|ดูคลิปได้เงิน|กดไลก์ได้เงิน/i, 
        score: 35, 
        reason: "หลอกชวนทำงานเสริมออนไลน์ รายได้เกินจริง (กดออเดอร์/ดูคลิป)" 
      },
      // 8. หลอกแจกรางวัลใหญ่
      { 
        pattern: /ผู้โชคดี|ได้รับรางวัล|iphone|ตั๋วเครื่องบินฟรี|แจกทอง/i, 
        score: 30, 
        reason: "หลอกว่าได้รับของรางวัลใหญ่ ทั้งที่ไม่ได้ร่วมกิจกรรม" 
      },
      // 9. ชวนแอดไลน์ส่วนตัว
      { 
        pattern: /แอดไลน์|ทักไลน์|แอดline|@\w+|line\.me/i, 
        score: 20, 
        reason: "ชักชวนให้แอดไลน์ส่วนตัวเพื่อพาเหยื่อไปคุยโน้มน้าวหลอกลวงต่อ" 
      },
      // 10. เร่งรัดเวลา
      { 
        pattern: /ด่วน|ภายในวันนี้|หมดอายุ|ทันที|เหลือ.*สิทธิ์/i, 
        score: 15, 
        reason: "ใช้เทคนิคเร่งรัดเวลา เพื่อให้เหยื่อรีบตัดสินใจโดยไม่ทันระวัง" 
      }
    ];

    const safeRules = [
      { 
        pattern: /(แพ็กเกจ.*เน็ต|เน็ตไม่อั้น|เช็กเน็ต|ซื้อแพ็กเกจ|\*\d{3}\*\d+[\d*]*#|Mbps|GB.*ชั่วโมง)/i, 
        score: -50, 
        reason: "เป็น SMS บริการแพ็กเกจโทรคมนาคมทางการของค่ายมือถือ (มีรหัส USSD กดสมัครจริง เช่น *900*...#)" 
      },
      { 
        pattern: /(รับชมซีรีส์|ดูซีรีส์|สตรีมมิ่ง|now ent|trueid|ttid\.co|netflix|viu|wetv|iqiyi)/i, 
        score: -50, 
        reason: "เป็น SMS ประชาสัมพันธ์คอนเทนต์บันเทิง/ซีรีส์ทางการจากแพลตฟอร์มสตรีมมิ่งที่ได้รับอนุญาต" 
      },
      { 
        pattern: /(รีเซ็ตรหัสผ่าน|reset.*password|เปลี่ยนรหัสผ่าน|แตะเพื่อรีเซ็ต)/i, 
        score: -50, 
        reason: "เป็นลิงก์ยืนยันรีเซ็ตรหัสผ่านทางการ (Password Reset Request) จากผู้ให้บริการ" 
      },
      { 
        pattern: /(otp.*ห้ามบอก|อย่าเปิดเผยรหัส|ref:|(telegram|google|apple|microsoft|whatsapp|steam|facebook|instagram|ig|line|meta|twitter|x|tiktok|shopee|lazada|binance).*(code|verification|login|ยืนยันตัวตน|รหัสยืนยัน)|verification\s*code|security\s*code|login\s*code|tap on this link to log in)/i, 
        score: -50, 
        reason: "เป็นรหัสยืนยันความปลอดภัย OTP / Login Verification Code ทางการจากแพลตฟอร์มมาตรฐานสากล (2-Factor Authentication)" 
      },
      { pattern: /รพ\.|โรงพยาบาล|นัดหมายพบแพทย์|งดน้ำงดอาหาร/i, score: -40, reason: "การแจ้งเตือนนัดหมายตรวจสุขภาพจากสถานพยาบาล" },
      { pattern: /เงินเข้าบัญชี|โอนเงินสำเร็จ|ยอดเงินคงเหลือ/i, score: -40, reason: "การแจ้งเตือนธุรกรรมทางการเงินตามปกติของธนาคาร" },
      { pattern: /นำจ่ายสำเร็จแล้ว|ผู้รับ: นิติบุคคล/i, score: -35, reason: "การแจ้งเตือนสถานะพัสดุสำเร็จจริงตามปกติ" }
    ];

    const samples = {
      instagram: "แตะเพื่อรีเซ็ตรหัสผ่าน Instagram ของคุณ\nhttps://ig.me/23vODMVGWHkfH6e",
      trueid: "สำรับฆาตกร (Murder in The Kitchen) รับชมซีรีส์ไทยแนวพีเรียดสืบสวน ทุกวันอังคาร เวลา 19.00 น. สมัคร NOW ENT 199 บาท/เดือน แล้วดูเลย https://ttid.co/xTgv/tceu4and",
      telegram: "Telegram code: 19068\n\nYou can also tap on this link to log in:\nhttps://t.me/login/19068",
      heng: "HENG88 เว็บใหญ่ สายบาครบวงจร ระบบลื่น ไม้ใหญ่มั่นใจที่นี่ heng-88.net",
      truenet: "แพ็กเกจ เน็ต 4 Mbps 1GB 6ชั่วโมง ใช้งานได้ถึง 07/10/2026 15:19:09 เช็กเงิน เช็กเน็ตคงเหลือ หรือซื้อแพ็กเกจเสริมเฉพาะสำหรับคุณได้ที่ tmn.app.link/EASYCHECK แนะนำ! เน็ตไม่อั้น 4Mbps 1วัน 32บ. (ไม่รวมVAT) กด *900*3888# โทรออก หรือ tmn.app.link/C117 แนะนำ! แอป ทรู ไซเบอร์เซฟ โปร ป้องกันมิจฉาชีพออนไลน์ บล็อก/แจ้งเตือนสายเรียกเข้า และ SMS อันตราย พร้อมฟรีประกันไซเบอร์ 30,000บ. และเน็ต 2GB แค่ 59บ./30วัน (ไม่รวม VAT) สมัครกด *900*7537# หรือ https://ss.true.th/s/pro",
      slot: "☀️ แสงตะวันสาดส่อง PG ไหลรัว WIN+98% กำไรฉ่ำๆ citly.me/dlfby4",
      parcel: "Flash Express: พัสดุหมายเลข TH0928374 ของคุณตกค้างเนื่องจากที่อยู่ไม่ชัดเจน กรุณายืนยันและชำระค่าธรรมเนียมจัดส่งใหม่ด่วนที่ bit.ly/flash-tracking-th",
      loan: "ธนาคารอนุมัติสินเชื่อเงินด่วนให้คุณ 100,000 บาท ดอกเบี้ย 0% ไม่เช็คเครดิตบูโร ผ่อนสบายเดือนละ 1,200 บาท แอดไลน์รับเงินด่วน @fastloan99",
      electric: "การไฟฟ้าส่วนภูมิภาค: ตรวจพบเงินประกันการใช้มิเตอร์ไฟฟ้าตกค้าง 3,500 บาท กรุณากดลิงก์เพื่อรับเงินคืนภายในวันนี้ pea-refund.vip",
      bank: "ธนาคารกสิกรไทย: บัญชีของท่านถูกระงับชั่วคราวเนื่องจากมีความพยายามเข้าสู่ระบบจากอุปกรณ์อื่น กรุณายืนยันตัวตนทันทีที่ kbank-secure-login.xyz",
      job: "ยินดีด้วย! คุณได้รับสิทธิ์ทำงานโปรโมทสินค้าออนไลน์ ทำที่บ้านวันละ 900-1500 บาท ไม่จำกัดวุฒิ สนใจแอดไลน์ @parttime_thai ด่วน",
      otp: "รหัส OTP ของคุณคือ 839201 (Ref: K92A) ใช้สำหรับยืนยันการทำรายการ ห้ามบอกรหัสนี้แก่ผู้อื่นทุกกรณี ธนาคารไม่มีนโยบายสอบถามรหัสนี้",
      salary: "เงินเข้าบัญชี xxx-x-12345-x จำนวน 35,000.00 บาท เมื่อ 30/09/26 17:30 น. ยอดเงินคงเหลือ 42,150.00 บาท",
      doctor: "รพ.จุฬาลงกรณ์: แจ้งเตือนนัดหมายตรวจสุขภาพ วันที่ 15 ต.ค. เวลา 09:00 น. กรุณางดน้ำและอาหารหลัง 20:00 น. แผนกอายุรกรรม",
      chat: "แม่จ๋า วันนี้หนูเลิกงานประมาณ 6 โมงเย็นนะ ฝากแม่ช่วยเปิดแอร์รอหน่อยจ้า เดี๋ยวซื้อกับข้าวเข้าไปกินด้วยกันนะ"
    };
    // ฐานข้อมูลและระบบแกะรอยปลายทางลิงก์ (URL Redirect Resolver & Deep Inspector)
    function resolveKnownRedirect(url) {
      const u = url.toLowerCase();
      if (u.includes('ig.me') || u.includes('instagram.com')) {
        return {
          dest: 'https://www.instagram.com/accounts/password/reset/ (หน้าเว็บรีเซ็ตรหัสผ่านทางการของ Instagram)',
          domain: 'instagram.com',
          owner: 'Instagram (แอปโซเชียลมีเดียในเครือ Meta)',
          purpose: 'รีเซ็ตรหัสผ่านบัญชี Instagram (Password Reset)',
          isOfficial: true
        };
      }
      if (u.includes('fb.me') || u.includes('facebook.com')) {
        return {
          dest: 'https://www.facebook.com (Facebook Official)',
          domain: 'facebook.com',
          owner: 'Facebook / Meta Platforms Inc.',
          purpose: 'บริการทางการของ Facebook / Meta',
          isOfficial: true
        };
      }
      if (u.includes('lin.ee') || u.includes('line.me')) {
        return {
          dest: 'https://line.me (LINE Official Platform)',
          domain: 'line.me',
          owner: 'LINE Corporation / LY Corporation',
          purpose: 'บริการทางการของ LINE',
          isOfficial: true
        };
      }
      if (u.includes('ttid.co')) {
        return {
          dest: 'https://myaccount.trueid.net/checkout?productCode=TVS_SYNC_NOWTM_1',
          domain: 'trueid.net',
          owner: 'TrueID / TrueVisions NOW (สตรีมมิ่งความบันเทิง)',
          purpose: 'สมัครบริการสตรีมมิ่ง TrueID NOW รับชมซีรีส์/ภาพยนตร์ "สำรับฆาตกร"',
          isOfficial: true
        };
      }
      if (u.includes('tmn.app.link')) {
        return {
          dest: 'https://www.truemoney.com (TrueMoney In-App Actions)',
          domain: 'truemoney.com',
          owner: 'TrueMoney / True Corporation',
          purpose: 'ตรวจสอบยอดเงิน เช็กเน็ตคงเหลือ หรือซื้อแพ็กเกจเสริม TrueMoney ทางการ',
          isOfficial: true
        };
      }
      if (u.includes('t.me')) {
        return {
          dest: 'https://telegram.org (Official Telegram Web / Login)',
          domain: 'telegram.org',
          owner: 'Telegram (แอปส่งข้อความสากล)',
          purpose: 'ยืนยันตัวตนเข้าสู่ระบบบัญชี Telegram (2FA / Login Verification Code)',
          isOfficial: true
        };
      }
      if (u.includes('ss.true.th')) {
        return {
          dest: 'https://ss.true.th/s/pro (True CyberSafe Official Promotion)',
          domain: 'true.th',
          owner: 'True / TrueMove H',
          purpose: 'สมัครบริการ ทรู ไซเบอร์เซฟ โปร ป้องกันสายมิจฉาชีพและ SMS อันตราย',
          isOfficial: true
        };
      }
      if (u.includes('m.ais.co.th')) {
        return {
          dest: 'https://www.ais.th (AIS eService Official)',
          domain: 'ais.th',
          owner: 'AIS (ผู้ให้บริการเครือข่ายมือถือ)',
          purpose: 'ตรวจสอบแพ็กเกจและบริการทางการของ AIS',
          isOfficial: true
        };
      }
      if (u.includes('bit.ly') || u.includes('citly.me') || u.includes('xyz') || u.includes('vip') || u.includes('top') || u.includes('heng-88')) {
        return {
          dest: url + ' ⚠️ (ตรวจพบเป็นลิงก์ย่อ/โดเมนแปลกปลอม)',
          domain: 'unverified-external',
          owner: 'ไม่ปรากฏผู้ถือครองทางการ (เว็บไซต์แปลกปลอมนอกระบบ)',
          purpose: 'ล่อลวงให้คลิกเพื่อดูดรหัสผ่าน ข้อมูลส่วนบุคคล หรือชวนเล่นการพนัน',
          isOfficial: false
        };
      }
      
      const isOfficial = officialDomainRegex.test(url);
      return {
        dest: url,
        domain: url,
        owner: isOfficial ? 'ผู้ให้บริการทางการที่ได้รับการรับรองความปลอดภัย' : 'ไม่ปรากฏผู้ถือครองทางการ (เว็บไซต์แปลกปลอม)',
        purpose: isOfficial ? 'เข้าใช้งานบริการทางการตามปกติ' : 'เสี่ยงเป็นหน้าเว็บหลอกลวงหรือดักขโมยข้อมูล (Phishing/Malware)',
        isOfficial: isOfficial
      };
    }


    /* ============================================================
       analyze(): ตรรกะเดิมจาก scanMessage แยกออกมาเป็นฟังก์ชันล้วน (ไม่แตะ DOM)
       คืนค่าเป็นอ็อบเจ็กต์ที่เก็บลง localStorage ได้ (JSON-safe)
       ============================================================ */
    const BASE_SCORE = 15;
    const scamRuleLabels = [
      'ลิงก์ต้องสงสัย', 'เว็บพนันออนไลน์', 'แอบอ้างขนส่ง', 'เงินกู้นอกระบบ', 'แอบอ้างหน่วยงานรัฐ',
      'แอบอ้างธนาคาร', 'งานเสริมหลอกลวง', 'แจกรางวัลลวง', 'ชวนแอดไลน์', 'เร่งรัดเวลา'
    ];
    const safeRuleLabels = [
      'แพ็กเกจเครือข่ายจริง', 'คอนเทนต์สตรีมมิ่ง', 'รีเซ็ตรหัสผ่านจริง', 'รหัสยืนยัน OTP',
      'นัดหมายแพทย์', 'ธุรกรรมธนาคาร', 'สถานะพัสดุสำเร็จ'
    ];

    function collectRanges(text, rule, type) {
      const ranges = [];
      if (rule.pattern) {
        const re = new RegExp(rule.pattern.source, rule.pattern.flags.replace('g', '') + 'g');
        let m;
        while ((m = re.exec(text)) !== null) {
          if (m[0].length === 0) { re.lastIndex++; continue; }
          ranges.push([m.index, m.index + m[0].length, type]);
        }
      } else if (rule.check) {
        getUntrustedUrls(text).forEach(u => {
          let from = 0, i;
          while ((i = text.indexOf(u, from)) !== -1) { ranges.push([i, i + u.length, type]); from = i + u.length; }
        });
      }
      return ranges;
    }

    function analyze(rawText) {
      const text = rawText.trim();
      let hasDanger = false;
      let riskScore = BASE_SCORE;
      const reasons = [];
      const contrib = [];
      let ranges = [];

      const context = analyzeMessageContext(text);

      scamRules.forEach((rule, i) => {
        let matched = false, reason = rule.reason;
        if (rule.check) {
          const res = rule.check(text);
          if (res.match) { matched = true; reason = res.reason; }
        } else if (rule.pattern && rule.pattern.test(text)) {
          matched = true;
        }
        if (matched) {
          riskScore += rule.score;
          reasons.push({ text: reason, type: 'danger' });
          contrib.push({ label: scamRuleLabels[i] || 'กฎมิจฉาชีพ', score: rule.score });
          ranges = ranges.concat(collectRanges(text, rule, 'danger'));
          hasDanger = true;
        }
      });

      let override = null;
      if (context.isMismatch) {
        hasDanger = true; reasons.unshift({ text: context.linkAnalysis.text, type: 'danger' }); riskScore = 99; override = 'ลิงก์แอบอ้างแอปจริง';
      } else if (context.isGambling) {
        hasDanger = true; reasons.unshift({ text: context.linkAnalysis.text, type: 'danger' }); riskScore = 99; override = 'เว็บพนันออนไลน์';
      } else if (context.isUntrustedLink) {
        hasDanger = true; reasons.unshift({ text: context.linkAnalysis.text, type: 'danger' }); riskScore = Math.max(riskScore, 95); override = 'ลิงก์ไม่ใช่โดเมนทางการ';
      } else if (context.isAnonymousThreat) {
        hasDanger = true;
        reasons.unshift({ text: "ข้อความไม่ระบุชื่อแอป แต่มีพฤติกรรมข่มขู่สร้างความกลัว (หมายศาล/ระงับบัญชี/ดำเนินคดี) เข้าข่ายกลวิธีแก๊งคอลเซ็นเตอร์", type: 'danger' });
        riskScore = 85; override = 'ข่มขู่คล้ายแก๊งคอลเซ็นเตอร์';
      } else if (context.isAnonymousBait) {
        hasDanger = true;
        reasons.unshift({ text: "ข้อความไม่ระบุชื่อแอป แต่มีการล่อลวงผลประโยชน์/เงินกู้ด่วน 0%/งานออนไลน์ เข้าข่ายมิจฉาชีพหลอกลวง", type: 'danger' });
        riskScore = 90; override = 'ล่อลวงผลประโยชน์';
      } else if (context.isBenignConversation) {
        reasons.push({ text: "บทสนทนาในชีวิตประจำวันของคนในครอบครัวหรือเพื่อน ไม่พบสัญญาณหลอกลวง", type: 'safe' });
        riskScore = 1;
      }

      const allUrls = extractUrls(text);
      const untrustedUrls = getUntrustedUrls(text);
      if (allUrls.length > 0 && untrustedUrls.length === 0 && !hasDanger) {
        reasons.push({
          text: "ตรวจพบลิงก์หรือโดเมนทางการที่ผ่านการรับรองความปลอดภัย (Verified Official Domain): " + allUrls.slice(0, 2).join(', '),
          type: 'safe'
        });
        allUrls.slice(0, 2).forEach(u => {
          const i = text.indexOf(u);
          if (i !== -1) ranges.push([i, i + u.length, 'safe']);
        });
        riskScore = 1;
      }

      if (!hasDanger) {
        safeRules.forEach((rule, i) => {
          if (rule.pattern.test(text)) {
            riskScore += rule.score;
            reasons.push({ text: rule.reason, type: 'safe' });
            contrib.push({ label: safeRuleLabels[i] || 'กฎความปลอดภัย', score: rule.score });
            ranges = ranges.concat(collectRanges(text, rule, 'safe'));
          }
        });
        if (context.matchedEntity && context.linkAnalysis.status === 'safe') riskScore = 1;
        if (context.isNeutral) riskScore = 1;
      } else {
        const isGambling = gamblingPattern.test(text);
        if (isGambling || context.isMismatch || reasons.filter(r => r.type === 'danger').length >= 2) {
          if (!context.isAnonymousThreat && !context.isAnonymousBait) riskScore = 99;
        }
      }

      const percent = Math.min(Math.max(riskScore, 1), 99);
      const level = percent >= 60 ? 'danger' : percent >= 30 ? 'warn' : 'safe';

      // หมวดของข้อความ: กฎที่ให้คะแนนสูงสุด หรือสาเหตุที่ระบบปรับคะแนนทับ
      let category;
      if (level === 'safe') {
        const generic = !context.appCategory || context.appCategory === 'ข้อความทั่วไป';
        category = generic && contrib.length ? contrib[0].label : (context.appCategory || 'ข้อความปกติ');
      } else {
        // ใช้กฎที่ให้คะแนนสูงสุด (ไม่นับ "ลิงก์ต้องสงสัย" เพราะกว้างเกินไป) ถ้าไม่มีให้ใช้สาเหตุที่ปรับคะแนนทับ
        const top = contrib.filter(c => c.score > 0 && c.label !== 'ลิงก์ต้องสงสัย').sort((a, b) => b.score - a.score)[0];
        category = top ? top.label : (override || (contrib.length ? 'ลิงก์ต้องสงสัย' : 'ข้อความน่าสงสัย'));
      }

      // คำสำคัญที่พบ (ไม่ซ้ำ ไม่ยาวเกินไป)
      const wanted = level === 'safe' ? 'safe' : 'danger';
      const kw = [];
      ranges.filter(r => r[2] === wanted).forEach(r => {
        const w = text.slice(r[0], r[1]).trim();
        if (w.length >= 2 && w.length <= 28 && !kw.includes(w)) kw.push(w);
      });

      let link = null;
      if (allUrls.length > 0) {
        const res = resolveKnownRedirect(allUrls[0]);
        link = { raw: allUrls[0], dest: res.dest, owner: res.owner, purpose: res.purpose, isOfficial: !!res.isOfficial };
      }

      return {
        text: text, percent: percent, level: level, category: category,
        reasons: reasons, contrib: contrib, ranges: ranges, keywords: kw.slice(0, 10),
        context: {
          appName: context.appName || '', appCategory: context.appCategory || '', intent: context.intent || '',
          hierarchyTierBadge: context.hierarchyTierBadge || '',
          linkAnalysis: { status: context.linkAnalysis.status, text: context.linkAnalysis.text }
        },
        link: link
      };
    }
    global.SG = global.SG || {};
    global.SG.analyze = analyze;
    global.SG.samples = samples;
    global.SG.BASE_SCORE = BASE_SCORE;
})(window);
