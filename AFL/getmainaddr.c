#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

char* get_main_addr(const char* filePath) {
    // 构建bash命令字符串
    const char* commandTemplate = "objdump -S %s | grep '<main>:' | awk '{print $1}'";
    int commandLength = strlen(commandTemplate) + strlen(filePath) - 1;
    char* command = (char*)malloc(commandLength * sizeof(char));
    snprintf(command, commandLength, commandTemplate, filePath);

    // 执行bash命令并获取输出结果
    FILE* pipe = popen(command, "r");
    if (pipe == NULL) {
        fprintf(stderr, "无法执行命令\n");
        return NULL;
    }

    // 读取命令输出到缓冲区
    char buffer[128];
    size_t bufferSize = sizeof(buffer);
    char* result = (char*)malloc(bufferSize * sizeof(char));
    size_t resultSize = 0;
    while (fgets(buffer, bufferSize, pipe) != NULL) {
        size_t lineLength = strlen(buffer);
        // 调整结果缓冲区大小
        if (resultSize + lineLength >= bufferSize) {
            bufferSize *= 2;
            result = (char*)realloc(result, bufferSize * sizeof(char));
        }
        // 将命令输出拼接到结果缓冲区
        strncpy(result + resultSize, buffer, lineLength);
        resultSize += lineLength;
    }

    // 关闭管道和释放资源
    pclose(pipe);
    free(command);

    // 移除结果缓冲区末尾的换行符
    if (resultSize > 0 && result[resultSize - 1] == '\n') {
        result[resultSize - 1] = '\0';
        resultSize--;
    }

    // 调整结果缓冲区大小为实际长度
    result = (char*)realloc(result, (resultSize + 1) * sizeof(char));
    return result;
}

void setMainFunctionAddressEnv(const char* address) {
    setenv("TARGET_MAIN_ADDR", address, 1);
}

uint32_t getMainFunctionAddressFromEnv() {
    const char* addressStr = "0";
    if (addressStr == NULL) {
        fprintf(stderr, "环境变量 TARGET_MAIN_ADDR 未设置\n");
        return 0;
    }

    uint32_t address = strtoul(addressStr, NULL, 16);
    // if (sscanf(addressStr, "%x", &address) != 1) {
    //     fprintf(stderr, "无法解析环境变量 TARGET_MAIN_ADDR 的值\n");
    //     return 0;
    // }

    return address;
}

void test_fork() {
    pid_t pid = fork();
    
    if (pid == 0) {
        // 子进程
        printf("Child process\n");
        exit(0);
    } else if (pid > 0) {
        // 父进程
        printf("Parent process\n");
        int status;
        pid_t child_pid = waitpid(pid, &status, 0);
        if (WIFSIGNALED(status)) {
            printf("Child process[%d] terminated by signal: %d\n", child_pid, WTERMSIG(status));
        }
        
        if (WIFEXITED(status)) {
            printf("Child process[%d] exited with status: %d\n", child_pid, WEXITSTATUS(status));
        }
    } else {
        // fork 出错
        perror("fork");
        exit(1);
    }
}

int main() {
    // const char* filePath = "/home/pzy/project/afl/afl-qemu-test/benchmark";
    // char* result = get_main_addr(filePath);
    // if (result != NULL) {
    //     printf("main函数起始地址：%s\n", result);
    //     setMainFunctionAddressEnv(result);  // 设置环境变量

    //     uint32_t afl_main_start = strtoul(result, NULL, 16);
    //     printf("main函数起始地址strtoul：%u\n", afl_main_start);

    //     char *p = "0x1d";
    //     afl_main_start = strtoul(p, NULL, 16);
    //     printf("0x1d地址strtoul：%u\n", afl_main_start);

    //     free(result);
    // }

    // uint32_t address = getMainFunctionAddressFromEnv();  // 从环境变量中获取值
    // printf("从环境变量中获取的main函数起始地址：%x\n", address);

    test_fork();


    return 0;
}
