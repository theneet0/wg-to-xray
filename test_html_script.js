const fs = require("fs");
const vm = require("vm");

const html = fs.readFileSync("index.html", "utf-8");

// Extract script content
const scriptMatch = html.match(/<script>([\s\S]*?)<\/script>/i);
if (!scriptMatch) {
  console.error("❌ No script tag found in index.html!");
  process.exit(1);
}

const scriptCode = scriptMatch[1];

// Create mock DOM elements
const mockElements = {};
function createMockElement(id) {
  return {
    id,
    value: id === "optTag" ? "wireguard" : (id === "optMtu" ? "1420" : (id === "optDomain" ? "ForceIP" : "")),
    checked: id === "optNoKernelTun",
    textContent: "",
    innerHTML: "",
    placeholder: "",
    style: {},
    classList: {
      add: () => {},
      remove: () => {}
    },
    addEventListener: (event, handler) => {
      mockElements[`${id}_${event}`] = handler;
    },
    click: () => {},
    setAttribute: () => {},
    getAttribute: () => "",
  };
}

const elementIds = [
  "dropzone", "fileInput", "selectFileBtn", "loadedFileBadge", "loadedFileName", "removeFileBtn",
  "configText", "charCount", "loadSampleBtn", "clearInputBtn", "convertBtn",
  "optTag", "optDomain", "optMtu", "optNoKernelTun", "optWrapOutbounds",
  "viewAllBtn", "viewUriBtn", "viewJsonBtn", "sectionUri", "sectionJson",
  "outputUriPre", "copyUriBtn",
  "outputJsonPre", "copyJsonBtn", "downloadJsonBtn",
  "messagesList", "toast", "toastText"
];

const elements = {};
elementIds.forEach(id => {
  elements[id] = createMockElement(id);
});

// Create a sandbox to run the converter functions
const sandbox = {
  console: console,
  document: {
    documentElement: { lang: "en" },
    querySelectorAll: () => [],
    getElementById: (id) => elements[id] || createMockElement(id),
    createElement: () => ({ style: {}, appendChild: () => {}, select: () => {} }),
    body: { appendChild: () => {}, removeChild: () => {} },
  },
  navigator: { clipboard: { writeText: async () => {} } },
  URL: { createObjectURL: () => "blob:fake-url", revokeObjectURL: () => {} },
  FileReader: class {
    readAsText() {}
  },
  setTimeout: (fn) => fn(),
};

vm.createContext(sandbox);
vm.runInContext(scriptCode, sandbox);

console.log("Script evaluated successfully in sandbox.");

// 1. Test XSS sanitization
console.log("\nTesting XSS prevention:");
const sanitized = sandbox.escapeHtml("<script>alert('xss')</script>&\"test'");
if (sanitized.includes("<script>") || sanitized.includes("'xss'")) {
  console.error("❌ escapeHtml failed to sanitize HTML entities!");
  process.exit(1);
}
console.log("  ✅ escapeHtml sanitizes properly:", sanitized);

sandbox.showError("<script>alert(1)</script>");
if (elements["messagesList"].innerHTML.includes("<script>")) {
  console.error("❌ showError allowed raw unescaped HTML injection!");
  process.exit(1);
}
console.log("  ✅ showError safely escapes error message!");

sandbox.renderSuccess("<img src=x onerror=alert(1)>", { peers: [], interface: { privatekey: "k" } }, ["<script>warning</script>"], 1);
if (elements["messagesList"].innerHTML.includes("<img src=x") || elements["messagesList"].innerHTML.includes("<script>")) {
  console.error("❌ renderSuccess allowed raw unescaped HTML injection!");
  process.exit(1);
}
console.log("  ✅ renderSuccess safely escapes filenames and warnings!");

// 2. Test MTU UI Override & Dual Output (JSON + WireGuard URI)
console.log("\nTesting MTU UI Override & Dual Output (JSON + URI):");
elements["configText"].value = `[Interface]
PrivateKey = 8Mn46OZH7DTRrHPAejXiGZ1Ide/GCBawNt6NDHJpfU8=
Address = 10.0.0.2/32
MTU = 1380
[Peer]
PublicKey = bwanSi8gvcFJkSBbC5K0ED/gZ7r8tNq8Twp3YqOigEQ=
Endpoint = vip.jojo-data.com:46341`;

elements["optTag"].value = "owner";
elements["optMtu"].value = "1420"; // User override

sandbox.doConvert("test.conf");

if (elements["optMtu"].value !== "1420") {
  console.error(`❌ doConvert unexpectedly overwrote optMtu.value! Got "${elements["optMtu"].value}", expected "1420"`);
  process.exit(1);
}
console.log("  ✅ doConvert preserves user-typed MTU in optMtu.value!");

// Check that generated JSON in outputJsonPre used the user's MTU 1420
if (!elements["outputJsonPre"].innerHTML.includes("1420")) {
  console.error(`❌ MTU 1420 was not found in outputJsonPre.innerHTML: ${elements["outputJsonPre"].innerHTML}`);
  process.exit(1);
}
console.log("  ✅ Generated output JSON contains MTU 1420 override!");

// Check that generated URI in outputUriPre matches wireguard:// schema with tag owner
const expectedUri = "wireguard://8Mn46OZH7DTRrHPAejXiGZ1Ide%2FGCBawNt6NDHJpfU8%3D@vip.jojo-data.com:46341?address=10.0.0.2%2F32&mtu=1420&publickey=bwanSi8gvcFJkSBbC5K0ED%2FgZ7r8tNq8Twp3YqOigEQ%3D#owner";
if (!elements["outputUriPre"].textContent.includes(expectedUri)) {
  console.error(`❌ Generated URI mismatch!\nGot:      ${elements["outputUriPre"].textContent}\nExpected: ${expectedUri}`);
  process.exit(1);
}
console.log("  ✅ Generated WireGuard URI matches user specification exactly!");

// 3. Test View Filter Switching
console.log("\nTesting View Filter Modes:");
sandbox.setViewMode("uri");
if (elements["sectionUri"].style.display !== "flex" || elements["sectionJson"].style.display !== "none") {
  console.error("❌ setViewMode('uri') did not toggle sections correctly!");
  process.exit(1);
}
console.log("  ✅ setViewMode('uri') shows URI section and hides JSON section");

sandbox.setViewMode("json");
if (elements["sectionUri"].style.display !== "none" || elements["sectionJson"].style.display !== "flex") {
  console.error("❌ setViewMode('json') did not toggle sections correctly!");
  process.exit(1);
}
console.log("  ✅ setViewMode('json') shows JSON section and hides URI section");

sandbox.setViewMode("all");
if (elements["sectionUri"].style.display !== "flex" || elements["sectionJson"].style.display !== "flex") {
  console.error("❌ setViewMode('all') did not show both sections!");
  process.exit(1);
}
console.log("  ✅ setViewMode('all') displays both URI and JSON sections");

// 4. Test file picker reset
console.log("\nTesting File Picker Reset:");
elements["fileInput"].value = "C:\\fakepath\\test.conf";
sandbox.openFilePicker();
if (elements["fileInput"].value !== "") {
  console.error("❌ openFilePicker failed to clear fileInput.value!");
  process.exit(1);
}
console.log("  ✅ openFilePicker clears fileInput.value to ensure re-selecting same file fires change event!");

console.log("\n✅ ALL ADVANCED index.html VALIDATION CHECKS PASSED!");
