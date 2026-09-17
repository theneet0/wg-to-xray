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
  "outputPre", "copyJsonBtn", "downloadJsonBtn",
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

sandbox.renderSuccess("<img src=x onerror=alert(1)>", { peers: [], interface: { privatekey: "k" } }, ["<script>warning</script>"]);
if (elements["messagesList"].innerHTML.includes("<img src=x") || elements["messagesList"].innerHTML.includes("<script>")) {
  console.error("❌ renderSuccess allowed raw unescaped HTML injection!");
  process.exit(1);
}
console.log("  ✅ renderSuccess safely escapes filenames and warnings!");

// 2. Test MTU UI Override
console.log("\nTesting MTU UI Override:");
elements["configText"].value = `[Interface]
PrivateKey = yAnz5TF+lXXJTr13wFwYxLzQv8n9v6p1Xy0Z1A2B3C4=
Address = 10.0.0.2/32
MTU = 1380
[Peer]
PublicKey = bmXE4J8vgEz9dmypCYlhUSxDZITQqde6Set8TeQUuGs=
Endpoint = 198.51.100.1:51820`;

elements["optMtu"].value = "1400"; // User typed 1400

sandbox.doConvert("test.conf");

if (elements["optMtu"].value !== "1400") {
  console.error(`❌ doConvert unexpectedly overwrote optMtu.value! Got "${elements["optMtu"].value}", expected "1400"`);
  process.exit(1);
}
console.log("  ✅ doConvert preserves user-typed MTU in optMtu.value!");

// Check that generated JSON in outputPre used the user's MTU 1400, not the file's 1380
if (!elements["outputPre"].innerHTML.includes("1400")) {
  console.error(`❌ MTU 1400 was not found in outputPre.innerHTML: ${elements["outputPre"].innerHTML}`);
  process.exit(1);
}
console.log("  ✅ Generated output HTML contains MTU 1400 override!");

// 3. Test file picker reset
console.log("\nTesting File Picker Reset:");
elements["fileInput"].value = "C:\\fakepath\\test.conf";
sandbox.openFilePicker();
if (elements["fileInput"].value !== "") {
  console.error("❌ openFilePicker failed to clear fileInput.value!");
  process.exit(1);
}
console.log("  ✅ openFilePicker clears fileInput.value to ensure re-selecting same file fires change event!");

console.log("\n✅ ALL ADVANCED index.html VALIDATION CHECKS PASSED!");
