var cyAsm;
var cyFunc;

var selectedNodeId;
var functionView = true;
var callHandlerAdded = false;

var asmContainer;
var funcContainer;
var clickedNode;
var btnLoadBlocks;
var functionSelect;

var dataFunctionGraph;
var datraFunctionAssembly;

const START_LABELS = new Set([
  '_start', '__start', 'start', 'main',
  '__libc_start_main', '_main'
]);


cytoscape.use(cytoscapeDagre);
cytoscape.use(cytoscapeKlay);

const regPattern = /^(?:[re]?(?:[abcd]x|[sd]i|[sb]p|sp)|[abcd][hl]|[re]?ip|r(?:1[0-5]|[8-9])(?:[bwd])?)$/i;
const escapeHtml = (s) =>
        String(s)
        .replaceAll("&", "&amp;")
        .replaceAll("<", "&lt;")
        .replaceAll(">", "&gt;")
        .replaceAll('"', "&quot;")
        .replaceAll("'", "&#39;");


const breakpoints = new Set();
const excludes = new Set();

const DEFAULT_W = 150;
const DEFAULT_H = 50;

function addrTextToKey(addrText){
  return (addrText || "").replace(":", "").trim().toLowerCase();
}


function addrToNode(addrHex){
    if (!cyFunc) {
        console.error("Cytoscape instance not found");
        return;
    }

    const intIdentifier = parseInt(addrHex, 16);
    const node = cyFunc.getElementById(intIdentifier);
    return node;
}

function lineToHtml(line) {
    const s = escapeTabsToSpaces(String(line));

    // match: optional whitespace + 0x...:
    const m = s.match(/^\s*(0x[0-9a-fA-F]+:)\s*(.*)$/);
    if (!m) return escapeHtml(s);

    const addr = m[1];        // "0x....:"
    var rest = m[2] ?? "";  // everything after it

    // match operation
    const mOp = rest.match(/^\s*([a-zA-Z]+)(.*)$/);
    const op = mOp[1];
    rest = mOp[2] ?? "";

    var callBoolean = false;

    if(op == "call"){
        const mOperands = rest.split(',').map(s => s.trim());
        const operand = mOperands[0];
        result = `<span class="addr">${escapeHtml(addr)}</span> ` + `<span class="call-op" data-op="call" value="${escapeHtml(operand)}"><span class="op">${escapeHtml(op)}</span>`
        callBoolean = true;
    }else {
        result = `<span class="addr">${escapeHtml(addr)}</span> <span class="op">${escapeHtml(op)}</span>`
    }

    // match operands split on ','
    const mOperands = rest.split(',').map(s => s.trim());
    for(let i = 0; i < mOperands.length; i++) {
        const operand = mOperands[i];
        //if operand 0x... then imm
        if (operand.match(/^0x[0-9a-fA-F]+$/)) {
            result += ` <span class="imm">${escapeHtml(operand)}</span>`;
        } 
        // if register (e.g. eax, ebx, rax, rbx, etc.)
        else if (regPattern.test(operand)) {
            result += ` <span class="reg">${escapeHtml(operand)}</span>`;
        }
        else{
            result += ` <span class="mem">${escapeHtml(operand)}</span>`;
        }

        if(i < mOperands.length - 1) {
            result += `<span class="text">,</span>`;
        }
    }
    if(callBoolean){
        result += `</span>`;
    }

    return result;
}

function autosizeNodesFromHtml(cy, {
  minW = 10, minH = 10,
  maxW = 420, maxH = 1500,
  padX = 0, padY = 0
} = {}) {
  // one hidden measurer for all nodes
  const measurer = document.createElement("div");
  measurer.style.position = "fixed";
  measurer.style.left = "-99999px";
  measurer.style.top = "-99999px";
  measurer.style.visibility = "hidden";
  measurer.style.pointerEvents = "none";
  measurer.style.width = "fit-content";
  measurer.style.height = "fit-content";

  // IMPORTANT: match your label DOM structure + CSS class
  measurer.innerHTML = `<div class="asm"></div>`;
  const box = measurer.firstElementChild;

  document.body.appendChild(measurer);

  cy.batch(() => {
    cy.nodes().forEach(n => {
      const html = n.data("html") ?? "";
      box.innerHTML = html;

      // If you use max-width in CSS, measurement will reflect wrapping.
      const r = box.getBoundingClientRect();

      let w = Math.ceil(r.width + padX);
      let h = Math.ceil(r.height + padY);

      w = Math.max(minW, Math.min(maxW, w));
      h = Math.max(minH, Math.min(maxH, h));

      n.data("w", w);
      n.data("h", h);
    });
  });

  measurer.remove();
}

function normalizeId(id) {
  return String(id).toLowerCase();
}

function escapeTabsToSpaces(s) {
  return String(s).replace(/\t/g, "    ");
}

function showView(which) {
  const funcEl = document.getElementById("cyFunc");
  const asmEl  = document.getElementById("cyAsm");

  if (which === "func") {
    funcEl.classList.remove("hidden");
    asmEl.classList.add("hidden");
    exportSvgBtn.classList.add("hidden");
    cyFunc?.resize();
    cyFunc?.fit(undefined, 30);
  } else {
    asmEl.classList.remove("hidden");
    funcEl.classList.add("hidden");
    exportSvgBtn.classList.remove("hidden");
    cyAsm?.resize();
    cyAsm?.fit(undefined, 30);
  }
}

function applyBreakpointsToOverlay(){
  const root = document.getElementById("cyAsm");
  if (!root) return;

  root.querySelectorAll(".addr").forEach(el => {
    const key = addrTextToKey(el.textContent);
    el.classList.toggle("has-bp", breakpoints.has(key));
  });
}

function applyExcludesToOverlay(){
    const root = document.getElementById("cyAsm");
    if (!root) return;

    root.querySelectorAll(".addr").forEach(el => {
        const key = addrTextToKey(el.textContent);
        el.classList.toggle("is-excl", excludes.has(key));
    });
}

function ColorNodeInGraph(node){
    cyFunc.nodes().removeStyle();
    if (node.nonempty()) {
        node.style({
            'background-color': 'red',
            'border-color': 'red'
        });  
    } else {
        console.warn("Node with identifier " + identifier + " not found in the graph.");
    }
}

function clickedNodeSelect(node){
    if (functionView) {
        ColorNodeInGraph(node);
    
        cyFunc.animate(
            {
                center: { eles: node },
                zoom: 1.5
            },
            { duration: 500 }
        );
    }

    if (node.nonempty()) {
        clickedNode.textContent = `${node.data('label')} (id: ${node.id()})`;
        btnLoadBlocks.disabled = false;
    } else {
        clickedNode.textContent = `(not found in graph)`;
    }
}

function buildCyFunc(idContainer, nodes, edges){
    const cy = cytoscape({
        container: document.getElementById(idContainer),
        elements: [...nodes, ...edges],
        style: [
            {
            selector: 'node',
            style: {
                'label': 'data(label)',
                'text-wrap': 'wrap',
                'text-max-width': 150,
                'font-size': 20,

                'text-valign': 'top',
                'text-margin-y': -15,

                'background-color': '#2563eb',
                'color': '#111827',
                'text-outline-width': 6,
                'text-outline-color': '#ffffff'
            }
            },
            {
                selector: 'edge',
                style: {
                    'curve-style': 'bezier',
                    'target-arrow-shape': 'triangle',
                    'width': 2,
                    'line-color': '#9ca3af',
                    'target-arrow-color': '#9ca3af',
                }
            }
        ],
        wheelSensitivity: 0.08,
    });
    return cy;
}

function buildCyAsm(idContainer){
    const cy = cytoscape({
        container: document.getElementById(idContainer),
        style: [
            {
                selector: "node",
                style: {
                    // IMPORTANT: label is no longer your disasm; the plugin draws HTML.
                    "label": "",
                    "shape": "rectangle",

                    // Use fixed size (recommended with HTML overlay)
                    "width": "data(w)",
                    "height": "data(h)",
                    "padding": "10px",

                    "background-color": "#ffffff",
                    "border-width": 1,
                    "border-color": "rgba(192, 192, 192, 1)",
                }
                },
                {
                selector: "edge",
                style: {
                    "curve-style": "taxi",
                    "taxi-direction": "auto",
                    "taxi-turn": "10px",
                    "taxi-turn-min-distance": "2px",
                    

                    "target-arrow-shape": "triangle",
                    "width": 4,
                    "line-color": "#9ca3af",
                    "target-arrow-color": "#9ca3af",
                }
            }
        ],
        wheelSensitivity: 0.08,
    });
    return cy;
}

function plotFunctionAssembly(data) {

    cyAsm = buildCyAsm('cyAsm');

    console.log("Function assembly data:", data);

    const posById = new Map();
    const layoutNodes = data?.layout?.nodes ?? {};
    for (const [rawId, b] of Object.entries(layoutNodes)) {
        const id = normalizeId(rawId);
        const x = (b.cx != null) ? b.cx : (b.x + (b.w ?? 0) / 2);
        const y = (b.cy != null) ? b.cy : (b.y + (b.h ?? 0) / 2);
        posById.set(id, { x, y, w: b.w, h: b.h });
    }

    // 1) Dedupe nodes (keep largest duplicate)
    const nodeById = new Map();
    for (const n of (data.nodes ?? [])) {
        const id = normalizeId(n.id ?? n.addr);
        const prev = nodeById.get(id);
        if (!prev || (n.size ?? 0) > (prev.size ?? 0)) nodeById.set(id, n);
    }

    node_0 = data.nodes[0];
    capstoneArray = node_0.capstone;
    header_line = `<span class="text"><span class="data_type">${data.return_type}</span> <span class="mem">${data.function.name}</span>(${data.arg_types.map((arg_type, index) => `<span class="data_type">${arg_type}</span> arg_${index}`).join(", ")})</span><br/>`;
    capstoneArray.unshift(header_line);
    node_0.capstone = capstoneArray;
    data.nodes[0] = node_0;


    // 2) Build nodes with positions from layout
    const nodes = [...nodeById.values()].map(n => {
        const id = normalizeId(n.id ?? n.addr);
        const rawLines = Array.isArray(n.capstone) ? n.capstone : [];

        // Convert disasm lines to safe HTML lines
        var htmlLines;
        if(n == data.nodes[0]){
            htmlLines = rawLines.map((line, i) => (i === 0 ? line : lineToHtml(line)));
        }
        else{
            htmlLines = rawLines.map(lineToHtml);
        }

        const htmlBody = htmlLines.length ? htmlLines.join("<br/>") : "(no disassembly)";
        const p = posById.get(id);

        const labelText = htmlLines
            .map(s => s
            .replace(/<br\s*\/?>/gi, "\n")
            .replace(/<\/?[^>]+>/g, "")   // strip tags
            .replace(/&nbsp;/g, " ")
            .replace(/&lt;/g, "<")
            .replace(/&gt;/g, ">")
            .replace(/&amp;/g, "&")
            )
            .join("\n");

        return {
            data: {
                id,
                label: id,
                html: htmlBody,
                labelText: labelText,
                w: p?.w ?? DEFAULT_W,
                h: p?.h ?? DEFAULT_H,
            },
            position: p ? { x: p.x, y: p.y } : undefined,
        };
    });

    // 3) Dedupe edges
    const edgeSeen = new Set();
    const edges = [];
    (data.edges ?? []).forEach((e, i) => {
        const src = normalizeId(e.src);
        const dst = normalizeId(e.dst);
        const jumpkind = e.jumpkind ?? "transition";
        const key = `${src}->${dst}::${jumpkind}`;
        if (edgeSeen.has(key)) return;
        edgeSeen.add(key);
        edges.push({
        data: { id: `${key}#${i}`, source: src, target: dst, jumpkind },
        classes: jumpkind
        });
    });

    cyAsm.add([...nodes, ...edges]);

    // 4) Create/refresh HTML labels (do this AFTER cy.add)
    // Clear previous overlays if you redraw often:
    if (cyAsm._htmlLabelCleanup) cyAsm._htmlLabelCleanup();

    const api = cyAsm.nodeHtmlLabel(
        [{
        query: "node",
        valign: "center",
        halign: "center",
        tpl: (d) => `<div class="asm" data-node-id="${d.id}">${d.html ?? ""}</div>`
        }],
        
        { enablePointerEvents: true } // set true if you want clickable HTML
    );

    const runAutosize = () => {
        requestAnimationFrame(() => {
            requestAnimationFrame(() => {
            autosizeNodesFromHtml(cyAsm, {
                minW: 10, minH: 10,
                maxW: 1000,
                padX: 0, padY: 0,   // padding now lives in .asm CSS
                combine: (node, measured) => ({
                w: Math.max(node.data("w") ?? 0, measured.w),
                h: Math.max(node.data("h") ?? 0, measured.h),
                })
            });

            // refresh view + HTML overlay
            cyAsm.nodes().forEach(n => n.emit("position"));
            cyAsm.resize();
            cyAsm.fit(undefined, 30);
            });
        });
    };

    (document.fonts?.ready ? document.fonts.ready.then(runAutosize) : runAutosize());

    // Save cleanup hook if plugin returns one (varies by version)
    cyAsm._htmlLabelCleanup = api?.destroy || api?.remove || null;

    // Event handling: clickable assembly
    const container = cyAsm.container();
    // remove old handler if you redraw often
    if(callHandlerAdded == false){
        callHandlerAdded = true;
        container.removeEventListener("pointerdown", onAsmClick);

        function onAsmClick(e) {
            // prove the handler runs

            // Text-node safe: make sure we have an Element
            const t = (e.target && e.target.nodeType === Node.ELEMENT_NODE)
                ? e.target
                : e.target?.parentElement;

            if (!t) return;

            const elCall = t.closest(".call-op");
            if (elCall){
                const asmRoot = elCall.closest(".asm");
                const nodeId = asmRoot?.dataset?.nodeId;/**/

                console.log("Clicked call-op:", elCall, "in node:", nodeId);
                clickedCallHandler(elCall, e);
            }

            const elAddr = t.closest(".addr");
            if (elAddr){
                const asmRoot = elAddr.closest(".asm");
                const nodeId = asmRoot?.dataset?.nodeId;/**/

                console.log("Clicked addr:", elAddr, "in node:", nodeId);
                clickedAddrHandler(elAddr, e);
            }

            
        }

        container.addEventListener("pointerdown", onAsmClick);
    }
    

    // 5) Layout
    /*const layout = cyAsm.layout({name: "klay",
        padding: 10,
        nodeDimensionsIncludeLabels: true,   // important
        klay: {
            direction: "DOWN",
            edgeRouting: "ORTHOGONAL",
            crossingMinimization: "LAYER_SWEEP",

            // more breathing room
            spacing: 80,
            nodeLayering: "NETWORK_SIMPLEX",
            inLayerSpacingFactor: 1.4,
            edgeSpacingFactor: 1.2,

            // helps keep edges off nodes
            borderSpacing: 40
        }});*/

    let bpRaf = null;
    let exclRaf = null;
    function scheduleBpApply(){
        if (bpRaf) return;
        bpRaf = requestAnimationFrame(() => {
            bpRaf = null;
            applyBreakpointsToOverlay();
        });
    }
    function scheduleExclApply(){
        if (exclRaf) return;
        exclRaf = requestAnimationFrame(() => {
            exclRaf = null;
            applyExcludesToOverlay();
        });
    }

    cyAsm.on("render pan zoom", scheduleBpApply);
    cyAsm.on("render pan zoom", scheduleExclApply);
    scheduleBpApply();
    scheduleExclApply();


    const layout = cyAsm.layout({ name: "preset", padding: 10 });

    layout.on("layoutstop", () => {
        cyAsm.resize();
        cyAsm.fit(undefined, 30);
    });

    layout.run();


    showView("asm");
}

function plotFunctionGraph(data) {
    const nodes = data.nodes.map(n => ({
        data: {
            id: String(n.id),  // IMPORTANT: ids as strings
            label: n.name ?? String(n.id)
        }
    }));

    const edges = data.links.map((e, i) => ({
        data: {
            id: `${e.source}->${e.target}#${e.key ?? 0}#${i}`, // unique edge id
            source: String(e.source),
            target: String(e.target),
            key: e.key ?? 0,
            kind: e.kind ?? 'call'
        }
    }));

    cyFunc = buildCyFunc('cyFunc', nodes, edges);

    const start = cyFunc.nodes().filter(n => {
        const label = String(n.data('label') ?? '').trim();
        const lower = label.toLowerCase();
        return START_LABELS.has(label) || START_LABELS.has(lower);
    }).first();

    const root = start.nonempty() ? start : cyFunc.nodes().filter(n => n.indegree() === 0).first();

    console.log("Using root node: ", root);

    const layout = cyFunc.layout({
        name: 'breadthfirst',
        directed: false,
        roots: root,
        padding: 30,
        spacingFactor: 1.5,
        grid: false,
        avoidOverlap: true,
        nodeDimensionsIncludeLabels: true
    });

    layout.run();

    // Optional: click node to highlight outgoing edges
    cyFunc.on('tap', 'node', evt => {
        const n = evt.target;

        selectedNodeId = n.id();
        clickedNodeSelect(n);
    });

    cyFunc.on('tap', 'edge', (evt) => {
        const edge = evt.target;
        const target = edge.target(); // the node at the arrow end

        selectedNodeId = target.id();
        clickedNodeSelect(target);
    });

    const cyContainer = document.getElementById('cyFunc');
    cyFunc.on('mouseover', 'edge', () => {
        cyContainer.style.cursor = 'pointer';
    });

    cyFunc.on('mouseout', 'edge', () => {
        cyContainer.style.cursor = 'default';
    });

    cyFunc.on('mouseover', 'node', () => {
        cyContainer.style.cursor = 'pointer';
    });

    cyFunc.on('mouseout', 'node', () => {
        cyContainer.style.cursor = 'default';
    });

    showView("func");
}

function goToFunction(addr){
  console.log("Going to function at address:", addr);
  if (!addr) {
    console.warn("No addr provided to goToFunction()");
    return;
  }
  selectedNodeId = addr;
  getFunctionAssembly();
}

function clickedCallHandler(element, event) {
  event.preventDefault();
  event.stopPropagation();

  // Capture addr NOW (so it can't go stale)
  const addr = element.getAttribute("value"); // or element.dataset.addr

  showMiniMenu(event.clientX, event.clientY, [
    { label: "Go to function", onClick: () => goToFunction(addr) },
    //{ label: "Close", onClick: hideMiniMenu },
  ]);
}

function placeBreakpointAtAddress(addr) {
    sendBreakpointToServer(addr);

    breakpoints.add(addrTextToKey(addr));
    applyBreakpointsToOverlay();
};

function removeBreakpointAtAddress(addr) {
    removeBreakpointToServer(addr);

    breakpoints.delete(addrTextToKey(addr));
    applyBreakpointsToOverlay();
};


function placeExcludeAtAddress(addr) {
    sendExcludeToServer(addr);

    excludes.add(addrTextToKey(addr));
    applyExcludesToOverlay();
}

function removeExcludeAtAddress(addr) {
    removeExcludeToServer(addr);

    excludes.delete(addrTextToKey(addr));
    applyExcludesToOverlay();
}



function clickedAddrHandler(element, event) {
    event.preventDefault();
    event.stopPropagation();

    const addrText = element.textContent || "";
    const addr = addrText.replace(":", ""); // remove trailing colon if present

    if(element.classList.contains("has-bp")){
        showMiniMenu(event.clientX, event.clientY, [
            { label: `Copy address ${addr}`, onClick: () => {
                navigator.clipboard.writeText(addr).then(() => {
                    console.log(`Copied address ${addr} to clipboard`);
                }).catch(err => {
                    console.error('Failed to copy address: ', err);
                });
            }},
            { label: `Remove breakpoint`, onClick: () => removeBreakpointAtAddress(addr) },
            //{ label: "Close", onClick: hideMiniMenu },
        ]);
        return;
    }
    else if(element.classList.contains("is-excl")){
        showMiniMenu(event.clientX, event.clientY, [
            { label: `Copy address ${addr}`, onClick: () => {
                navigator.clipboard.writeText(addr).then(() => {
                    console.log(`Copied address ${addr} to clipboard`);
                }).catch(err => {
                    console.error('Failed to copy address: ', err);
                });
            }},
            { label: `Remove Exclude`, onClick: () => removeExcludeAtAddress(addr) },
            //{ label: "Close", onClick: hideMiniMenu },
        ]);
        return;
    }

    showMiniMenu(event.clientX, event.clientY, [
      { label: `Copy address ${addr}`, onClick: () => {
          navigator.clipboard.writeText(addr).then(() => {
              console.log(`Copied address ${addr} to clipboard`);
          }).catch(err => {
              console.error('Failed to copy address: ', err);
          });
      }},
      { label: `Place breakpoint`, onClick: () => placeBreakpointAtAddress(addr) },
      { label: `Exclude`, onClick: () => placeExcludeAtAddress(addr) },
      //{ label: "Close", onClick: hideMiniMenu },
    ]);
  }

function showMiniMenu(x, y, items) {
  hideMiniMenu(); // remove any existing

  const menu = document.createElement("div");
  menu.id = "mini-menu";
  menu.className = "mini-menu";

  for (const item of items) {
    const btn = document.createElement("button");
    btn.type = "button";
    btn.textContent = item.label;
    btn.addEventListener("click", () => {
      hideMiniMenu();
      item.onClick?.();
    });
    menu.appendChild(btn);
  }

  document.body.appendChild(menu);

  // Position near cursor, but keep it in viewport
  const rect = menu.getBoundingClientRect();
  const padding = 8;

  let left = x + padding;
  let top  = y + padding;

  if (left + rect.width > window.innerWidth) left = x - rect.width - padding;
  if (top + rect.height > window.innerHeight) top = y - rect.height - padding;

  menu.style.left = `${Math.max(padding, left)}px`;
  menu.style.top  = `${Math.max(padding, top)}px`;

  // Close on outside click / escape
  setTimeout(() => {
    document.addEventListener("mousedown", onDocMouseDown, { once: true });
    document.addEventListener("keydown", onEsc, { once: true });
  }, 0);

  function onDocMouseDown(e) {
    if (!menu.contains(e.target)) hideMiniMenu();
  }
  function onEsc(e) {
    if (e.key === "Escape") hideMiniMenu();
  }
}

function hideMiniMenu() {
  document.getElementById("mini-menu")?.remove();
}