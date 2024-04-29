import importlib
import os
import inspect

def get_python_classes_in_folder(folder_path):
    python_classes = []

    # Traverse the directory structure recursively
    for root, dirs, files in os.walk(folder_path):
        for file in files:
            if file.endswith('.py'):
                file_path = os.path.join(root, file)
                classes = get_classes_from_file(file_path)
                python_classes.extend(classes)

    return python_classes

def get_classes_from_file(file_path):
    classes = []

    # Attempt to import the module dynamically
    module_name = os.path.splitext(os.path.basename(file_path))[0]
    spec = importlib.util.spec_from_file_location(module_name, file_path)
    if spec is not None:
        module = importlib.util.module_from_spec(spec)
        try:
            spec.loader.exec_module(module)

            # Iterate over the members of the module
            for name, obj in inspect.getmembers(module):
                # Check if the member is a class
                if inspect.isclass(obj):
                    classes.append(obj)
                
        except:
            pass
    return classes