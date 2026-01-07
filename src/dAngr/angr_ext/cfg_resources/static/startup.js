var functionMap = new Map();

document.addEventListener('DOMContentLoaded', () => {
    cyAsm = document.getElementById('cyAsm');
    cyFunc = document.getElementById('cyFunc');
    exportSvgBtn = document.getElementById('exportSvgBtn');
    clickedNode = document.getElementById('clickedNode');
    btnLoadBlocks = document.getElementById('btnLoadBlocks');
    functionSelect = document.getElementById('functionSelect');

    getFunctionsInformation();
    getFunctionGraph();

    btnLoadBlocks.addEventListener('click', () => {
        if (!selectedNodeId) {
            console.error("No node selected");
            return;
        }

        getFunctionAssembly();
    });

    document.getElementById("exportSvgBtn").addEventListener("click", () => {
        saveCyAsSvg("asm-cfg.svg");
    });
});
