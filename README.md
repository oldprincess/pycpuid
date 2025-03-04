# pycpuid

本项目使用MIT协议，如果您想要使用本项目，请仔细阅读MIT协议。

如果有任何疑问，请发 email 至 zirui.gong@foxmail.com

This software uses the MIT LICENSE. If you wish to use this software, please carefully read the text of the MIT LICENSE.

If you have any questions, please send an email to zirui.gong@foxmail.com

## 1 基本介绍

CPUID指令的纯Python接口，实际上是对Anders Høst的[cpuid.py](https://github.com/flababah/cpuid.py)的进一步包装

Pure Python interface to the CPUID instruction. Actually, it is a further packaging of Anders Høst's cpuid.py

## 2 使用说明

直接使用cpuid指令

directly using the cpuid instruction

```python
from pycpuid import CPUID

__cpuidex = CPUID()
print("__cpuidex(0):", __cpuidex(0))
# __cpuidex(0): (32, 1970169159, 1818588270, 1231384169)
```

测试CPU支持的指令集

test the instruction set supported by the CPU

```python
from pycpuid import InstructionSet

s = InstructionSet()

print("SSE is supported:", s.SSE())
# SSE is supported: True
```

详细样例参考demo.py文件

detailed example reference demo.py file

```shell
$ python demo.py
GenuineIntel
12th Gen Intel(R) Core(TM) i5-12500H
3DNOW not supported
3DNOWEXT not supported
ABM not supported
ADX supported
...(omit)
```

## 3 声明

本软件是AS IS的( 不提供任何保证， ( 不管是显式的还是隐式的，包括但不限于适销性保证、适用性保证、非侵权性保证 ) ) ，在任何情况下， ( 对于任何的权益追索、损失赔偿或者任何追责 ) ，作者或者版权所有人都不会负责。( 无论这些追责产生自合同、侵权，还是直接或间接来自于本软件以及与本软件使用或经营有关的情形 )

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
