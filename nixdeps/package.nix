{ pythonPackages
}:

pythonPackages.buildPythonPackage {
  name = "nixdeps";
  src = ./.;
  pythonImportsCheck = [ "nixdeps.setuptools" ];
  propagatedBuildInputs = [
    pythonPackages.setuptools
  ];
}

