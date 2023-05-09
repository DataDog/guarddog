!#/bin/sh

github_branch="$1"

if [ -z "${github_branch}" ]; then
	echo "[+] Please specify a github branch to use"
	exit 0
fi

echo "[+] Uninstalling the actual guarddog"
pip uninstall guarddog

echo "[+] Installing guarddog from your Github branch: ${github_branch}"
pip install "git+https://github.com/DataDog/guarddog.git@${github_branch}"
