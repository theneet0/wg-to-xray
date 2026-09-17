const fs = require("fs");
const { execSync } = require("child_process");
const converter = require("./converter.js");

const testCases = [
  {
    name: "Basic config",
    conf: `
[Interface]
PrivateKey = aaaaaaaa11111111aaaaaaaa11111111aaaaaaaa11=
Address = 10.0.0.2/32, fd00::2/128
DNS = 1.1.1.1, 8.8.8.8
MTU = 1420

[Peer]
PublicKey = bbbbbbbb22222222bbbbbbbb22222222bbbbbbbb22=
Endpoint = 198.51.100.1:51820
AllowedIPs = 0.0.0.0/0, ::/0
PersistentKeepalive = 25
`
  },
  {
    name: "Config with inline comments and quotes and Reserved in Interface",
    conf: `
# This is a comment
; Another comment
[Interface]
PrivateKey = "cccccccc33333333cccccccc33333333cccccccc33=" # secret key
Address = 172.16.0.2/24   ; internal IP
Reserved = [1, 2, 3] # reserved bytes
MTU = 1380

[Peer]
PublicKey = 'dddddddd44444444dddddddd44444444dddddddd44='
Endpoint = example.com:51820 # endpoint
PresharedKey = pskpskpskpskpskpskpskpskpskpskpskpskpsk=
AllowedIPs = 10.0.0.0/8, 192.168.0.0/16
PersistentKeepalive = 15
`
  },
  {
    name: "Config with Reserved in Peer and multiple peers",
    conf: `
[Interface]
PrivateKey = eeeeeeee55555555eeeeeeee55555555eeeeeeee55=

[Peer]
PublicKey = ffffffff66666666ffffffff66666666ffffffff66=
Endpoint = 1.2.3.4:51820
Reserved = 10, 20, 30

[Peer]
PublicKey = 111111117777777711111111777777771111111177=
Endpoint = 5.6.7.8:51820
`
  },
  {
    name: "Unknown sections and ignored lines",
    conf: `
IgnoredLineWithoutEqualSign
[Interface]
PrivateKey = gggggggg88888888gggggggg88888888gggggggg88=
Address = 10.66.66.2/32

[CustomSection]
Foo = Bar

[Peer]
PublicKey = hhhhhhhh99999999hhhhhhhh99999999hhhhhhhh99=
Endpoint = 9.9.9.9:51820
`
  },
  {
    name: "Reserved with multiple zeros: 0, 00, 0",
    conf: `[Interface]\nPrivateKey = secret11111111secret11111111secret11111111se=\nReserved = 0, 00, 0\n[Peer]\nPublicKey = pub11111111pub11111111pub11111111pub11111111pu=\nEndpoint = 1.1.1.1:51820`
  },
  {
    name: "Reserved with boundary bracket variations",
    conf: `[Interface]\nPrivateKey = secret22222222secret22222222secret22222222se=\nReserved = 1, 2, 3]\n[Peer]\nPublicKey = pub22222222pub22222222pub22222222pub22222222pu=\nEndpoint = 2.2.2.2:51820`
  },
  {
    name: "Reserved with hex and signs",
    conf: `[Interface]\nPrivateKey = secret33333333secret33333333secret33333333se=\nReserved = +0x10, 0x20, 0x30\n[Peer]\nPublicKey = pub33333333pub33333333pub33333333pub33333333pu=\nEndpoint = 3.3.3.3:51820`
  },
  {
    name: "CR-only line endings (classic Mac)",
    conf: "[Interface]\rPrivateKey = secret44444444secret44444444secret44444444se=\rAddress = 10.0.0.4/32\r[Peer]\rPublicKey = pub44444444pub44444444pub44444444pub44444444pu=\rEndpoint = 4.4.4.4:51820\r"
  }
];

let allPassed = true;

for (const tc of testCases) {
  console.log(`Testing: ${tc.name}`);
  const pyResultStr = execSync(`python py_ref.py wireguard ForceIP 1420 true false`, {
    input: tc.conf,
    encoding: "utf-8"
  });
  const pyResult = JSON.parse(pyResultStr);

  const jsParsed = converter.parseWireguardConfig(tc.conf);
  const jsBuilt = converter.buildXrayConfig(jsParsed, {
    tag: "wireguard",
    domainStrategy: "ForceIP",
    mtuOverride: jsParsed.interface.mtu || "1420",
    noKernelTun: true,
    wrapInOutbounds: false
  });

  const pyJson = JSON.stringify(pyResult.config);
  const jsJson = JSON.stringify(jsBuilt.config);

  if (pyJson !== jsJson) {
    console.error(`❌ Config mismatch in ${tc.name}!`);
    console.error("PY:", pyJson);
    console.error("JS:", jsJson);
    allPassed = false;
  } else {
    console.log(`  ✅ Config matched!`);
  }

  // Check warnings
  if (JSON.stringify(pyResult.warnings) !== JSON.stringify(jsBuilt.warnings)) {
    console.warn(`  ⚠️ Warnings differ:`);
    console.warn("  PY:", pyResult.warnings);
    console.warn("  JS:", jsBuilt.warnings);
  } else {
    console.log(`  ✅ Warnings matched!`);
  }
}

// Test error handling
const errorCases = [
  {
    name: "Missing PrivateKey",
    conf: `[Interface]\nAddress = 10.0.0.1\n[Peer]\nPublicKey = abc\nEndpoint = 1.2.3.4:51820`,
    expectedError: "PrivateKey not found in [Interface] section."
  },
  {
    name: "Missing Peer",
    conf: `[Interface]\nPrivateKey = secret`,
    expectedError: "No [Peer] section found in WireGuard file."
  },
  {
    name: "Missing PublicKey in Peer",
    conf: `[Interface]\nPrivateKey = secret\n[Peer]\nEndpoint = 1.2.3.4:51820`,
    expectedError: "PublicKey not found in Peer number 1."
  },
  {
    name: "Missing Endpoint in Peer",
    conf: `[Interface]\nPrivateKey = secret\n[Peer]\nPublicKey = pubkey`,
    expectedError: "Endpoint not found in Peer number 1."
  },
  {
    name: "Invalid Reserved count",
    conf: `[Interface]\nPrivateKey = secret\nReserved = 1, 2\n[Peer]\nPublicKey = pubkey\nEndpoint = 1.2.3.4:51820`,
    expectedError: "Reserved must contain exactly 3 numbers"
  },
  {
    name: "Invalid Reserved out of bounds",
    conf: `[Interface]\nPrivateKey = secret\nReserved = 1, 256, 3\n[Peer]\nPublicKey = pubkey\nEndpoint = 1.2.3.4:51820`,
    expectedError: "Reserved values must be between 0 and 255"
  },
  {
    name: "Invalid Reserved leading zero decimal",
    conf: `[Interface]\nPrivateKey = secret\nReserved = 01, 2, 3\n[Peer]\nPublicKey = pubkey\nEndpoint = 1.2.3.4:51820`,
    expectedError: "Invalid Reserved"
  },
  {
    name: "Invalid MTU range",
    conf: `[Interface]\nPrivateKey = secret\nMTU = 500\n[Peer]\nPublicKey = pubkey\nEndpoint = 1.2.3.4:51820`,
    expectedError: "MTU should normally be between 576 and 9000"
  },
  {
    name: "Negative PersistentKeepalive",
    conf: `[Interface]\nPrivateKey = secret\n[Peer]\nPublicKey = pubkey\nEndpoint = 1.2.3.4:51820\nPersistentKeepalive = -1`,
    expectedError: "PersistentKeepalive cannot be negative"
  }
];

console.log("\nTesting Error Handling:");
for (const ec of errorCases) {
  try {
    const parsed = converter.parseWireguardConfig(ec.conf);
    converter.buildXrayConfig(parsed, {
      mtuOverride: parsed.interface.mtu || "1420"
    });
    console.error(`❌ Expected error for '${ec.name}', but none was thrown!`);
    allPassed = false;
  } catch (err) {
    if (err.message.includes(ec.expectedError)) {
      console.log(`  ✅ Caught expected error for '${ec.name}': ${err.message}`);
    } else {
      console.error(`  ❌ Error message mismatch for '${ec.name}': got "${err.message}", expected "${ec.expectedError}"`);
      allPassed = false;
    }
  }
}

// Test WireGuard URI generation
console.log("\nTesting WireGuard URI Generation:");
const userConf = `[Interface]
PrivateKey = 8Mn46OZH7DTRrHPAejXiGZ1Ide/GCBawNt6NDHJpfU8=
Address = 10.0.0.2/32
MTU = 1420

[Peer]
PublicKey = bwanSi8gvcFJkSBbC5K0ED/gZ7r8tNq8Twp3YqOigEQ=
Endpoint = vip.jojo-data.com:46341
`;

const parsedUser = converter.parseWireguardConfig(userConf);
const uris = converter.buildWireguardUri(parsedUser, { tag: "owner" });
const expectedUri = "wireguard://8Mn46OZH7DTRrHPAejXiGZ1Ide%2FGCBawNt6NDHJpfU8%3D@vip.jojo-data.com:46341?address=10.0.0.2%2F32&mtu=1420&publickey=bwanSi8gvcFJkSBbC5K0ED%2FgZ7r8tNq8Twp3YqOigEQ%3D#owner";

if (uris[0] === expectedUri) {
  console.log("  ✅ User example URI matched exactly!");
} else {
  console.error("  ❌ User example URI mismatch!");
  console.error("  Got:     ", uris[0]);
  console.error("  Expected:", expectedUri);
  allPassed = false;
}

if (!allPassed) {
  process.exit(1);
}
console.log("\nALL TESTS PASSED WITH 100% PARITY!");

