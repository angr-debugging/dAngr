cytoscape.use(cytoscapeSvg);

function downloadTextFile(text, filename, mime = "text/plain") {
    const blob = new Blob([text], { type: mime + ";charset=utf-8" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = filename;
    document.body.appendChild(a);
    a.click();
    a.remove();
    URL.revokeObjectURL(url);
}

function saveCyAsSvg(filename = "graph.svg", opts = {}) {
    cyAsm.style()
    .selector("node")
    .style({
        "label": "data(labelText)",
        "text-wrap": "wrap",
        "text-max-width": 900,
        "font-family": "monospace",
        "font-size": 10,
        "text-valign": "center",
        "text-halign": "center"
    })
    .update();
    if (!cyAsm) throw new Error("saveCyAsSvg: cyAsm is required");
    if (typeof cyAsm.svg !== "function") {
        throw new Error("saveCyAsSvg: cyAsm.svg() missing. Did you load cytoscape-svg and call cytoscape.use(cytoscapeSvg)?");
    }

    cyAsm.resize();

    const svgStr = cyAsm.svg({
        full: true,
        scale: 1,
        ...opts
    });

    downloadTextFile(svgStr, filename, "image/svg+xml");

    cyAsm.style()
        .selector("node")
        .style({
            "label": "",
            "shape": "rectangle",

            // Use fixed size (recommended with HTML overlay)
            "width": "data(w)",
            "height": "data(h)",
            "padding": "10px",

            "background-color": "#ffffff",
            "border-width": 1,
            "border-color": "rgba(192, 192, 192, 1)",
        })
    .update();
}