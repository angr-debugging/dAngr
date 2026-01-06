

function getFunctionsInformation(){
    fetch('/functions')
    .then(response => response.json())
    .then(data => {
        const functions = data.functions;
        const functionSelect = document.getElementById('functionSelect');

        const optionGoBack = document.createElement('option');
        optionGoBack.value = 'go_back';
        optionGoBack.text = 'Full function CFG';
        optionGoBack.classList.add('p-1', 'hover:bg-slate-700', 'cursor-pointer', 'block', 'w-full');
        functionSelect.appendChild(optionGoBack);

        optionGoBack.addEventListener('click', () => {
            selectedNodeId = null;
            if (dataFunctionGraph)
                plotFunctionGraph(dataFunctionGraph);
        });

        const optionDefault = document.createElement('option');
        optionDefault.value = '';
        optionDefault.text = '-- Select a function --';
        optionDefault.classList.add('p-1', 'cursor-pointer', 'block', 'w-full');
        functionSelect.appendChild(optionDefault);

        functions.forEach(func => {
            const option = document.createElement('option');
            option.value = func.addr;
            option.text = func.name + ' (' + func.addr + ')';
            option.classList.add('p-1', 'hover:bg-slate-700', 'cursor-pointer', 'block', 'w-full');
            functionSelect.appendChild(option);

            
            option.addEventListener('click', () => {
                console.log("Function selected: ", func);
                
                const node = addrToNode(func.addr);
                selectedNodeId = node.id();
                clickedNodeSelect(node);
            });
        });
    });
}

function getFunctionGraph(){
    if (dataFunctionGraph){
        plotFunctionGraph(dataFunctionGraph);
        return;
    }

    fetch('/functions_graph')
        .then(response => response.json())
        .then(data => {
            dataFunctionGraph = data;
            plotFunctionGraph(data);
        })
        .catch(err => console.error('graph fetch/render error', err));
}

function getFunctionAssembly(){
    console.log("Loading function disassembly for node id:", selectedNodeId);
    fetch('/load_function_assembly', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json'
        },
        body: JSON.stringify({
            // get the currently selected node
            node_id: selectedNodeId
        })
    })
    .then(response => response.json())
    .then(data => {
        plotFunctionAssembly(data);
    })
    .catch(error => {
        console.error('Error loading function disassembly:', error);
    });
}

function manageBreakpointsAndExlcudes(type, action, addr) {
    fetch('/manage_breakpoints_excludes', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json'
        },
        body: JSON.stringify({
            item_type: type,
            action: action,
            address: addr
        })
    })
    .then(response => response.json())
    .then(data => {
        console.log(`${action} ${type} at ${addr}:`, data);
    })
    .catch(error => {
        console.error(`Error managing ${type} at ${addr}:`, error);
    });
}

function sendBreakpointToServer(addr){
    manageBreakpointsAndExlcudes('breakpoint', 'add', addr);
}

function removeBreakpointToServer(addr){
    manageBreakpointsAndExlcudes('breakpoint', 'remove', addr);
}

function removeExcludeToServer(addr){
    manageBreakpointsAndExlcudes('exclude', 'remove', addr);
}

function sendExcludeToServer(addr){
    manageBreakpointsAndExlcudes('exclude', 'add', addr);
}
