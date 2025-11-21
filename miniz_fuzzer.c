#include "miniz.h" 
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>

extern int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size == 0) return 0;
    
    // 1. 设置解压目标 (一个足够大的堆缓冲区)
    size_t out_size = 2 * size + 1024;
    void *out_buf = malloc(out_size);
    if (!out_buf) return 0;

    // 2. 调用核心解压函数 (会触发你植入的漏洞)
    size_t actual_size = 0;
    // 这里的函数调用会执行你在 miniz.c 中植入的 Double Free/Null Deref 逻辑
    tinfl_decompress_mem_to_heap(data, size, &actual_size, 0); 

    // 3. 清理 
    free(out_buf);
    
    return 0;
}
