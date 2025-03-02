# The MIT License (MIT)

# Copyright (c) 2024 oldprincess, https://github.com/oldprincess/pycpuid.git

# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:

# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.

# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
# EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
# MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
# IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM,
# DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR
# OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE
# OR OTHER DEALINGS IN THE SOFTWARE.

from pycpuid import InstructionSet

s = InstructionSet()


def support_message(isa_feature: str, is_supported: bool):
    print(isa_feature, "supported" if is_supported else "not supported")


print(s.Vendor())
print(s.Brand())
support_message("3DNOW", s._3DNOW())
support_message("3DNOWEXT", s._3DNOWEXT())
support_message("ABM", s.ABM())
support_message("ADX", s.ADX())
support_message("AES", s.AES())
support_message("AVX", s.AVX())
support_message("AVX2", s.AVX2())
support_message("AVX512CD", s.AVX512CD())
support_message("AVX512ER", s.AVX512ER())
support_message("AVX512F", s.AVX512F())
support_message("AVX512PF", s.AVX512PF())
support_message("BMI1", s.BMI1())
support_message("BMI2", s.BMI2())
support_message("CLFSH", s.CLFSH())
support_message("CMPXCHG16B", s.CMPXCHG16B())
support_message("CX8", s.CX8())
support_message("ERMS", s.ERMS())
support_message("F16C", s.F16C())
support_message("FMA", s.FMA())
support_message("FSGSBASE", s.FSGSBASE())
support_message("FXSR", s.FXSR())
support_message("HLE", s.HLE())
support_message("INVPCID", s.INVPCID())
support_message("LAHF", s.LAHF())
support_message("LZCNT", s.LZCNT())
support_message("MMX", s.MMX())
support_message("MMXEXT", s.MMXEXT())
support_message("MONITOR", s.MONITOR())
support_message("MOVBE", s.MOVBE())
support_message("MSR", s.MSR())
support_message("OSXSAVE", s.OSXSAVE())
support_message("PCLMULQDQ", s.PCLMULQDQ())
support_message("POPCNT", s.POPCNT())
support_message("PREFETCHWT1", s.PREFETCHWT1())
support_message("RDRAND", s.RDRAND())
support_message("RDSEED", s.RDSEED())
support_message("RDTSCP", s.RDTSCP())
support_message("RTM", s.RTM())
support_message("SEP", s.SEP())
support_message("SHA", s.SHA())
support_message("SSE", s.SSE())
support_message("SSE2", s.SSE2())
support_message("SSE3", s.SSE3())
support_message("SSE4.1", s.SSE41())
support_message("SSE4.2", s.SSE42())
support_message("SSE4a", s.SSE4a())
support_message("SSSE3", s.SSSE3())
support_message("SYSCALL", s.SYSCALL())
support_message("TBM", s.TBM())
support_message("XOP", s.XOP())
support_message("XSAVE", s.XSAVE())
support_message("AVX512VL", s.AVX512VL())
support_message("GFNI", s.GFNI())
support_message("VAES", s.VAES())
support_message("VPCLMULQDQ", s.VPCLMULQDQ())
