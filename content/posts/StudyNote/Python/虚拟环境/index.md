# python虚拟环境

python -m venv -h 查看帮助

python -m venv 虚拟环境的名字（文件夹）

pip install package_name -i https://pypi.tuna.tsinghua.edu.cn/simple
https://mirrors.aliyun.com/pypi/simple/
激活虚拟环境：在Scripts目录中有activate.bat文件，进行激活。

# anaconda虚拟环境

conda env list 查看虚拟环境

conda create  -n 虚拟环境的名字 创建环境

conda remove -n 虚拟环境的名字 -all 删除虚拟环境

activate envpython=3.10 进入环境

conda deactivate 退出环境

安装包

conda install package_name

conda update package_name

将 JupyterNoteBook 的 ipynb 格式导出为 MarkDown 格式

jupyter nbconvert 最小二乘法.ipynb --to markdown

