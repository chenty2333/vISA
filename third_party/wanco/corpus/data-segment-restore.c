typedef signed int int32_t;
typedef signed long long int64_t;
typedef unsigned char uint8_t;

__attribute__((import_module("env"), import_name("print_i32")))
void print_i32(int32_t value);

__attribute__((import_module("env"), import_name("sleep_msec")))
void sleep_msec(int32_t milliseconds);

struct retained_state {
    int32_t generation;
    int64_t wide;
    float single;
    double precision;
    uint8_t bytes[16];
};

static struct retained_state state = {
    7,
    0x1122334455667788LL,
    3.25f,
    19.5,
    {1, 3, 5, 7, 9, 11, 13, 15, 17, 19, 21, 23, 25, 27, 29, 31},
};

__attribute__((noinline))
static int32_t checkpoint_leaf(int32_t seed, int64_t wide, float single,
                               double precision) {
    int32_t counter = 0;
    while (counter < 12) {
        print_i32(900 + counter);
        sleep_msec(80);
        wide ^= 0x101LL + counter;
        single += 0.5f;
        precision -= 0.25;
        counter++;
    }
    return seed ^ (int32_t)wide ^ (int32_t)single ^ (int32_t)precision ^
           counter;
}

__attribute__((noinline))
static int32_t depth_two(int32_t seed) {
    int32_t local32 = seed + 41;
    int64_t local64 = state.wide ^ 0x0102030405060708LL;
    float local32f = state.single + 4.5f;
    double local64f = state.precision + 8.25;
    return checkpoint_leaf(local32, local64, local32f, local64f) ^ seed;
}

__attribute__((noinline))
static int32_t depth_one(int32_t seed) {
    int32_t retained = seed * 3 + state.generation;
    return depth_two(retained) + retained;
}

__attribute__((noinline))
static int32_t state_checksum(void) {
    int32_t value = state.generation ^ (int32_t)state.wide ^
                    (int32_t)state.single ^ (int32_t)state.precision;
    for (int32_t index = 0; index < 16; index++) {
        value = (value * 33) ^ state.bytes[index];
    }
    return value;
}

__attribute__((export_name("_start")))
void start(void) {
    state.generation = 73;
    state.wide = 0x7766554433221100LL;
    state.single = 14.75f;
    state.precision = 61.125;
    for (int32_t index = 0; index < 16; index++) {
        state.bytes[index] = (uint8_t)(0xa0 + index);
    }
    print_i32(depth_one(29));
    print_i32(state_checksum());
}
