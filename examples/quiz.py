import monkey

content = ''

image = ''.join(chr(x) for x in
[
0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a, 0x00, 0x00, 0x00, 0x0d,
0x49, 0x48, 0x44, 0x52, 0x00, 0x00, 0x00, 0x30, 0x00, 0x00, 0x00, 0x28,
0x08, 0x06, 0x00, 0x00, 0x00, 0xb8, 0x87, 0x79, 0x71, 0x00, 0x00, 0x00,
0x04, 0x73, 0x42, 0x49, 0x54, 0x08, 0x08, 0x08, 0x08, 0x7c, 0x08, 0x64,
0x88, 0x00, 0x00, 0x00, 0x09, 0x70, 0x48, 0x59, 0x73, 0x00, 0x00, 0x03,
0x2c, 0x00, 0x00, 0x03, 0x2c, 0x01, 0x90, 0x94, 0x1c, 0x83, 0x00, 0x00,
0x00, 0x19, 0x74, 0x45, 0x58, 0x74, 0x53, 0x6f, 0x66, 0x74, 0x77, 0x61,
0x72, 0x65, 0x00, 0x77, 0x77, 0x77, 0x2e, 0x69, 0x6e, 0x6b, 0x73, 0x63,
0x61, 0x70, 0x65, 0x2e, 0x6f, 0x72, 0x67, 0x9b, 0xee, 0x3c, 0x1a, 0x00,
0x00, 0x0b, 0x41, 0x49, 0x44, 0x41, 0x54, 0x78, 0xda, 0xc5, 0x99, 0x7b,
0x6c, 0x5b, 0xd7, 0x7d, 0xc7, 0x3f, 0xe7, 0xdc, 0x07, 0x49, 0x51, 0xd4,
0x83, 0xa2, 0x1e, 0xf1, 0x53, 0xb2, 0x5d, 0x5b, 0x88, 0xd5, 0xda, 0xf3,
0x62, 0x59, 0x8d, 0xd7, 0xcc, 0x71, 0x3b, 0x07, 0x1b, 0x86, 0xac, 0x58,
0xe7, 0x24, 0x76, 0x92, 0xc2, 0x49, 0x80, 0x60, 0x6b, 0xd7, 0x17, 0x32,
0x14, 0x29, 0xda, 0x6d, 0x19, 0xba, 0x66, 0xb3, 0xb7, 0x2e, 0xd8, 0x30,
0x2c, 0x59, 0xff, 0x58, 0xb2, 0xba, 0xb1, 0x9b, 0x64, 0xc1, 0x90, 0xc4,
0x49, 0xe7, 0x2c, 0xb6, 0xe1, 0x24, 0xae, 0x15, 0xcb, 0xad, 0xe3, 0x34,
0x7e, 0x49, 0xab, 0x6c, 0xbd, 0xac, 0x07, 0x25, 0x51, 0x12, 0x25, 0x8a,
0xe4, 0xe5, 0xbd, 0x67, 0xd7, 0x67, 0xa2, 0x4a, 0x50, 0x6c, 0x2a, 0xa7,
0x5e, 0xfb, 0x11, 0xbe, 0x38, 0xc0, 0xbd, 0xc4, 0xe5, 0xf7, 0x7b, 0xce,
0xef, 0x77, 0xcf, 0xa5, 0xae, 0x50, 0x4a, 0x71, 0xa3, 0x88, 0xbf, 0xd0,
0xda, 0x80, 0xc3, 0xdf, 0x48, 0x41, 0xab, 0x82, 0x25, 0x28, 0x2a, 0x10,
0x48, 0xc0, 0x05, 0xd2, 0x40, 0x52, 0x08, 0xde, 0x12, 0x4a, 0x3c, 0x11,
0xdd, 0xf5, 0xce, 0x49, 0x6e, 0x00, 0x37, 0x24, 0x40, 0xfc, 0x60, 0xeb,
0x5d, 0x02, 0xfe, 0x0a, 0xc1, 0x3a, 0x14, 0x82, 0xc5, 0x31, 0xeb, 0x29,
0xf6, 0xd7, 0x59, 0x1d, 0x9f, 0x63, 0xa7, 0x72, 0x7f, 0x2d, 0x01, 0x46,
0xff, 0xad, 0x39, 0x42, 0xa8, 0xe2, 0x0d, 0xa0, 0x95, 0x0f, 0x8b, 0x20,
0x25, 0x11, 0xdf, 0x88, 0xde, 0xf3, 0xce, 0x13, 0x7c, 0x10, 0xdf, 0xb9,
0xc5, 0x4a, 0x54, 0x53, 0x56, 0xbd, 0xf3, 0x47, 0x53, 0xa0, 0xd4, 0x2f,
0x1d, 0x60, 0xec, 0xe0, 0x96, 0x4f, 0x7b, 0xa8, 0x83, 0x02, 0x82, 0xdc,
0x00, 0x14, 0x9c, 0xad, 0x35, 0x53, 0xad, 0xec, 0x7c, 0x3f, 0x4b, 0x01,
0x53, 0x2f, 0xdc, 0x1a, 0xcd, 0xe6, 0x72, 0x7b, 0x81, 0x3f, 0x02, 0xaa,
0x80, 0x04, 0x8a, 0x27, 0x62, 0x56, 0xe3, 0xe3, 0xec, 0x7c, 0xde, 0xfd,
0x50, 0x01, 0x46, 0x9f, 0xdd, 0xf2, 0xfb, 0x48, 0xf5, 0x32, 0x20, 0xb8,
0x81, 0x08, 0x18, 0x33, 0x32, 0xc6, 0x2d, 0x55, 0x7b, 0x4e, 0x5e, 0x01,
0x48, 0xbc, 0x70, 0xcb, 0x0a, 0x37, 0x27, 0x4f, 0x02, 0x4b, 0x28, 0x42,
0x08, 0x9e, 0xa9, 0xb9, 0xe7, 0xd4, 0x03, 0xd7, 0x1d, 0x20, 0xf1, 0xfc,
0xe6, 0xad, 0xae, 0x2b, 0x8e, 0x03, 0x06, 0xd7, 0x81, 0x19, 0x6b, 0x21,
0xfc, 0x1b, 0x5f, 0x46, 0xda, 0x15, 0x28, 0x37, 0x8d, 0x33, 0xf8, 0x0e,
0xa9, 0xf3, 0x4f, 0xa3, 0x9c, 0x14, 0x45, 0x64, 0x31, 0xd5, 0xc7, 0x62,
0xe7, 0x4f, 0x77, 0x8d, 0xad, 0xdd, 0xfc, 0x96, 0x82, 0x5b, 0xa1, 0x34,
0x52, 0xca, 0x3b, 0xae, 0x2b, 0x40, 0xef, 0x81, 0x8f, 0x55, 0x97, 0x89,
0xe0, 0x10, 0x60, 0x73, 0x1d, 0x94, 0x7d, 0xf4, 0x61, 0xec, 0xe6, 0xcf,
0x92, 0x4e, 0x67, 0x29, 0x2f, 0x2f, 0x27, 0x8f, 0x97, 0x1e, 0x67, 0xfa,
0xf4, 0x5e, 0xb2, 0x7d, 0xc7, 0x28, 0x62, 0x0a, 0x21, 0x76, 0xa3, 0xd4,
0x21, 0x00, 0x37, 0xe7, 0x31, 0x78, 0x29, 0x8e, 0xeb, 0x7a, 0x34, 0xac,
0xae, 0x21, 0x10, 0xb6, 0xd1, 0x08, 0x0e, 0x5d, 0x57, 0x80, 0xd1, 0x03,
0xad, 0xc7, 0x11, 0xdc, 0xc6, 0x75, 0x60, 0x56, 0xaf, 0x23, 0xbb, 0x69,
0x1f, 0x87, 0x8f, 0x1c, 0x26, 0x5c, 0x1e, 0xe6, 0xdc, 0xb9, 0x73, 0x94,
0x87, 0x22, 0x7c, 0xe5, 0x4b, 0x8f, 0xa0, 0xf1, 0x1c, 0x26, 0x8f, 0x7e,
0x1e, 0x27, 0xfe, 0x2e, 0x45, 0x38, 0x80, 0x05, 0x70, 0xe9, 0xed, 0xcb,
0x8c, 0xf6, 0x24, 0x90, 0x86, 0x20, 0x18, 0x0e, 0x70, 0xf3, 0xf6, 0x35,
0xf9, 0x10, 0x9d, 0xe6, 0xa2, 0xcd, 0x3f, 0xdf, 0x76, 0x7b, 0xb1, 0x79,
0x23, 0xb2, 0x9c, 0xf2, 0x5b, 0xbe, 0x8a, 0x55, 0xbf, 0x19, 0xe5, 0x39,
0x78, 0xa9, 0x11, 0x52, 0xef, 0x3d, 0x45, 0xa6, 0xf7, 0xbf, 0xc9, 0x13,
0xde, 0xf4, 0x15, 0xbe, 0xf0, 0xe8, 0x9f, 0xd1, 0xd2, 0xb2, 0x9e, 0x44,
0x22, 0xc1, 0xf8, 0xf8, 0x38, 0x47, 0x8f, 0x1e, 0x65, 0xc3, 0x86, 0x8d,
0x6c, 0xdf, 0xf6, 0x49, 0x90, 0x16, 0x91, 0x4f, 0xec, 0x65, 0xe2, 0xf0,
0x1e, 0xbc, 0x99, 0x41, 0x0a, 0xd0, 0xe6, 0x27, 0xae, 0x4e, 0x92, 0x1a,
0x9f, 0xa1, 0xbc, 0xc2, 0x46, 0x08, 0x81, 0x94, 0x8a, 0x81, 0xf7, 0x06,
0x58, 0xf5, 0xf1, 0x26, 0x6d, 0xc1, 0x64, 0xb1, 0xb8, 0xde, 0x7e, 0x0a,
0xb0, 0x6f, 0x6a, 0x23, 0x73, 0xf3, 0xd7, 0xd8, 0x7f, 0xf8, 0x55, 0x0c,
0xe3, 0x1c, 0x7d, 0x3d, 0x7d, 0xdc, 0x7b, 0xcf, 0xfd, 0x34, 0x6d, 0xfd,
0x16, 0xc1, 0x8f, 0x7c, 0x86, 0xa9, 0x37, 0x1f, 0x01, 0x69, 0x32, 0x1b,
0x5c, 0xc3, 0xc9, 0x93, 0x3f, 0xa4, 0xb7, 0xb7, 0x87, 0x54, 0x2a, 0xa5,
0x03, 0xb8, 0xae, 0xcb, 0x6b, 0x3f, 0x78, 0x15, 0x1d, 0x00, 0x90, 0x81,
0x6a, 0xca, 0xfd, 0xa0, 0x53, 0x6f, 0x7d, 0xb5, 0x54, 0x63, 0x13, 0x2e,
0xb7, 0xb4, 0x79, 0x21, 0x41, 0x0a, 0x81, 0x61, 0xcc, 0x77, 0xb2, 0x92,
0x2c, 0x82, 0xf1, 0x67, 0xdb, 0x6e, 0x06, 0x96, 0x92, 0x47, 0x5a, 0xa4,
0x1a, 0x1f, 0x64, 0xef, 0x3f, 0xec, 0x63, 0x66, 0x66, 0x9a, 0x9e, 0x9e,
0x1e, 0xba, 0xaf, 0x74, 0xf3, 0x27, 0x5f, 0xfc, 0x63, 0x32, 0x99, 0x0c,
0x56, 0xdd, 0x26, 0x22, 0xb7, 0xfe, 0x35, 0x66, 0xe5, 0x1a, 0xc6, 0xc6,
0xc7, 0xc8, 0xe5, 0x72, 0xfa, 0x33, 0xf1, 0x78, 0x5c, 0x9b, 0x07, 0x58,
0xb1, 0x62, 0x25, 0x73, 0xe8, 0x63, 0x46, 0xc3, 0x56, 0x64, 0x59, 0x1d,
0xc5, 0x98, 0xb6, 0x41, 0xa8, 0xdc, 0xf2, 0x65, 0x13, 0x0a, 0xdb, 0x04,
0xfd, 0x31, 0xe0, 0x1f, 0xd3, 0x28, 0x3a, 0x16, 0x15, 0xc0, 0x93, 0xee,
0xb7, 0x28, 0x20, 0xb4, 0xf6, 0x2e, 0x2e, 0xf6, 0x24, 0x78, 0xfb, 0xc4,
0xdb, 0x1c, 0x3f, 0x7e, 0x9c, 0x63, 0xc7, 0x8e, 0x71, 0xe2, 0xc4, 0x09,
0x2e, 0x5e, 0xbc, 0xc0, 0x2b, 0xaf, 0xbe, 0x0c, 0x80, 0xbd, 0x64, 0x2b,
0x65, 0xeb, 0xf7, 0xd0, 0xd4, 0xd8, 0xc4, 0x7d, 0xbb, 0xef, 0xa7, 0x90,
0xca, 0xca, 0x4a, 0xb6, 0xdd, 0x76, 0x7b, 0xde, 0xbc, 0x0e, 0x98, 0xc9,
0x3a, 0x04, 0xd7, 0xfc, 0xe1, 0xc2, 0x00, 0x96, 0x24, 0x58, 0x66, 0xfb,
0xb2, 0x08, 0x86, 0x2d, 0x02, 0xfe, 0x18, 0x8e, 0x96, 0x01, 0xa0, 0x14,
0x47, 0x4c, 0x16, 0x85, 0xb8, 0xa3, 0xb8, 0x7c, 0xfa, 0x2f, 0x74, 0x32,
0x34, 0x34, 0xa4, 0x55, 0x48, 0x4d, 0xb4, 0x86, 0x3c, 0xa6, 0xdf, 0x1b,
0x00, 0x7f, 0xf1, 0xf5, 0xc7, 0x08, 0x06, 0x83, 0x74, 0x77, 0x77, 0xfb,
0x46, 0x33, 0x3c, 0xfe, 0xcd, 0xbf, 0x65, 0xa5, 0xbf, 0x02, 0x79, 0xf3,
0x79, 0x05, 0x96, 0x7c, 0x12, 0xfc, 0x1e, 0x2a, 0x44, 0x9a, 0x06, 0xb6,
0x6f, 0x5a, 0x08, 0x7c, 0x09, 0xad, 0x40, 0x75, 0x18, 0x00, 0x0b, 0xe7,
0x8d, 0xf9, 0xbb, 0xd0, 0xf0, 0xfe, 0x2d, 0x4d, 0x86, 0xe9, 0xed, 0x40,
0xd0, 0x00, 0x72, 0xd8, 0x53, 0xe2, 0x3f, 0xeb, 0x76, 0xb5, 0x0f, 0x0f,
0x3d, 0xf3, 0xf1, 0x46, 0x33, 0xe0, 0x5e, 0xa6, 0x80, 0xe8, 0xa7, 0x5f,
0x65, 0x7c, 0x46, 0xf0, 0x7b, 0x77, 0xde, 0xc1, 0x48, 0x7c, 0x84, 0x3c,
0xa1, 0x50, 0x88, 0xd7, 0x5f, 0x3b, 0xc2, 0xf2, 0x65, 0xcb, 0xf1, 0x3c,
0x4f, 0xcb, 0x34, 0x4d, 0x4a, 0xb0, 0xc0, 0xbc, 0xe3, 0x38, 0x94, 0x85,
0x82, 0xa4, 0x0e, 0xed, 0x00, 0x2f, 0x47, 0x1e, 0x37, 0xe3, 0x90, 0x1d,
0x4b, 0xea, 0x00, 0xcc, 0x05, 0xb0, 0x6b, 0x2b, 0x10, 0x52, 0xbe, 0x19,
0xdb, 0x75, 0xea, 0xb7, 0x25, 0x40, 0xfc, 0x40, 0xeb, 0x97, 0x0c, 0x53,
0x5d, 0x00, 0xf1, 0x14, 0x4a, 0x3c, 0x86, 0x52, 0x4f, 0x4a, 0xbc, 0xde,
0xd1, 0x83, 0x9b, 0xbf, 0x6d, 0xd8, 0xce, 0x9d, 0x14, 0x20, 0xac, 0x72,
0x64, 0xa8, 0x96, 0x58, 0x2c, 0xc6, 0x3f, 0xff, 0xd3, 0x93, 0x34, 0xaf,
0x6b, 0xa6, 0x2c, 0x54, 0xc6, 0xaa, 0xa6, 0xd5, 0xbc, 0xf4, 0xe2, 0xa1,
0xbc, 0xf9, 0xbc, 0xb1, 0xc5, 0x9a, 0xd7, 0x63, 0xd6, 0xc9, 0x61, 0x94,
0xd5, 0x53, 0x88, 0xb4, 0x4c, 0xcc, 0xe0, 0x35, 0x59, 0xe8, 0x31, 0x6c,
0x5f, 0x33, 0x0f, 0x9e, 0xf8, 0x3b, 0x00, 0x31, 0xf6, 0xfd, 0x2d, 0x3b,
0xfc, 0x2f, 0x3c, 0xcc, 0xcf, 0x67, 0x0a, 0xa8, 0x98, 0x0f, 0x60, 0x86,
0xa8, 0xd9, 0x79, 0xbc, 0xa4, 0x29, 0xc3, 0x30, 0x0a, 0xcd, 0xeb, 0x63,
0x91, 0x48, 0x64, 0x31, 0xe6, 0xb5, 0x6c, 0xdb, 0x26, 0xf0, 0xfe, 0x63,
0x38, 0xc3, 0xa7, 0x29, 0xc4, 0x4b, 0xa5, 0x41, 0x29, 0x74, 0x19, 0xf9,
0x9f, 0xc1, 0x34, 0xce, 0xc7, 0x76, 0x75, 0xb4, 0x80, 0x52, 0xd2, 0xbf,
0xe0, 0x23, 0x7c, 0x30, 0x15, 0x14, 0xa0, 0x72, 0xb3, 0x78, 0xe9, 0x04,
0x45, 0xe4, 0xcd, 0x2f, 0x30, 0x97, 0xcd, 0x66, 0x17, 0x61, 0x5e, 0x4b,
0x97, 0x87, 0xca, 0xa5, 0x29, 0x46, 0xda, 0x96, 0x2f, 0x13, 0xe1, 0x8f,
0xbe, 0x79, 0x14, 0xfc, 0xbd, 0x4e, 0x04, 0x48, 0x21, 0x44, 0x1b, 0x73,
0x38, 0x99, 0x1c, 0xbd, 0x67, 0xaf, 0xd2, 0x7d, 0xf2, 0x32, 0x13, 0x7d,
0x09, 0x5c, 0xc7, 0xa5, 0x14, 0xde, 0xcc, 0x00, 0x45, 0xe4, 0xcd, 0x2f,
0x30, 0x98, 0x4c, 0x26, 0x17, 0x63, 0x5e, 0xcb, 0xb2, 0x2c, 0xdc, 0xa9,
0x6e, 0x16, 0x60, 0x1a, 0xbe, 0x4c, 0xb4, 0x60, 0xd0, 0x7f, 0x6a, 0x7d,
0x76, 0x3e, 0x1c, 0x90, 0x04, 0x50, 0x4a, 0x71, 0xe6, 0xd0, 0x05, 0xc6,
0x7b, 0xc6, 0xc9, 0xcd, 0x66, 0x49, 0x0e, 0x26, 0x48, 0xf6, 0x8d, 0x53,
0x8a, 0xdc, 0x44, 0xf7, 0x62, 0xcc, 0xeb, 0x71, 0x7a, 0x7a, 0x1a, 0x55,
0x7c, 0x7e, 0xa1, 0xf4, 0x35, 0x6c, 0xa9, 0x10, 0x46, 0x84, 0x92, 0x08,
0xc1, 0x1c, 0x4f, 0x15, 0x3e, 0x72, 0x4b, 0x50, 0x9d, 0x00, 0x53, 0x23,
0xd3, 0x08, 0x3c, 0xec, 0x80, 0x81, 0x75, 0x4d, 0xb6, 0x89, 0xba, 0x76,
0xf1, 0x54, 0x86, 0x62, 0x32, 0xdd, 0x2f, 0x2f, 0xca, 0x7c, 0xbe, 0x0f,
0x04, 0xba, 0x3f, 0x0a, 0xcf, 0x2f, 0x30, 0x1f, 0x0e, 0x87, 0x09, 0xd9,
0x92, 0x48, 0xcb, 0x17, 0xb1, 0xab, 0x36, 0xf0, 0x01, 0x9c, 0xa1, 0x00,
0xa9, 0x24, 0xba, 0x9b, 0x33, 0xd3, 0x59, 0x02, 0x73, 0xe6, 0xed, 0x80,
0xa9, 0x77, 0x40, 0xc3, 0x92, 0xb8, 0x33, 0xb3, 0x14, 0xe3, 0x8c, 0xbe,
0x47, 0x6e, 0xa2, 0xeb, 0x17, 0x98, 0xd7, 0xd2, 0xb7, 0x51, 0xe5, 0x64,
0x30, 0x72, 0x33, 0xba, 0x44, 0x4a, 0xcd, 0xbc, 0x94, 0x92, 0xda, 0x9a,
0x28, 0xde, 0xf4, 0x30, 0x89, 0xf8, 0x18, 0x76, 0xc3, 0x36, 0x3f, 0xc4,
0x46, 0x4a, 0xe1, 0x09, 0xc6, 0x28, 0x40, 0xd6, 0xde, 0xdd, 0xf1, 0x03,
0x14, 0x47, 0x62, 0x8d, 0xd5, 0x84, 0x22, 0x01, 0xbd, 0x02, 0xa6, 0x2d,
0x31, 0x2d, 0x03, 0xc3, 0x97, 0x40, 0xa0, 0xb2, 0x0e, 0xc5, 0xa4, 0x3b,
0x9f, 0x2b, 0x0a, 0x50, 0x6c, 0x5e, 0xcf, 0xbe, 0xde, 0x1b, 0xc8, 0xcd,
0xa2, 0xd2, 0x93, 0x04, 0x49, 0x53, 0x5d, 0x55, 0x39, 0xdf, 0xf0, 0x4a,
0x29, 0xfd, 0x78, 0xdd, 0xb8, 0x72, 0x05, 0x46, 0x3a, 0x8e, 0x72, 0xd2,
0xcc, 0x8c, 0xf4, 0x63, 0x44, 0x1a, 0xb0, 0xa3, 0xbf, 0x89, 0x0c, 0xc4,
0x28, 0x46, 0x2a, 0xf6, 0x50, 0x80, 0xd4, 0xa9, 0xe0, 0x61, 0x69, 0xc8,
0x81, 0x86, 0xe6, 0x7a, 0x5d, 0x3a, 0xff, 0x67, 0x5e, 0x62, 0x98, 0x06,
0xd2, 0x94, 0xe0, 0xba, 0x0b, 0x03, 0xfc, 0xf4, 0x15, 0xbc, 0xa1, 0x13,
0xda, 0xc4, 0xcf, 0x31, 0xaf, 0x67, 0x36, 0x5a, 0x19, 0xc1, 0x4b, 0x27,
0x51, 0xb9, 0x0c, 0x6a, 0x26, 0x8e, 0x91, 0xec, 0xa7, 0xa1, 0x2a, 0x48,
0xd3, 0xb2, 0x06, 0xd6, 0x34, 0x2e, 0xe3, 0xa6, 0xea, 0x10, 0x8c, 0x5f,
0xd2, 0xe7, 0xdc, 0xd4, 0x04, 0xfa, 0x4e, 0xa4, 0x5c, 0x10, 0x12, 0xbb,
0xea, 0xa3, 0x94, 0xe0, 0xfe, 0xe4, 0x77, 0xb7, 0xd4, 0x50, 0x18, 0xa0,
0x6e, 0xf7, 0xa9, 0x6e, 0xa4, 0xd8, 0x1e, 0xa9, 0xaf, 0x18, 0x8c, 0xad,
0xad, 0xc7, 0x0c, 0x58, 0x18, 0x73, 0x21, 0xa4, 0x1f, 0x42, 0x6f, 0x1c,
0x0b, 0x7e, 0x37, 0x28, 0x92, 0x27, 0xff, 0x92, 0x80, 0x9a, 0x06, 0x58,
0x60, 0x1e, 0xd0, 0x9b, 0x9d, 0x98, 0x1d, 0x05, 0x37, 0xed, 0x2b, 0x83,
0x72, 0xb3, 0xa4, 0x7b, 0xcf, 0x92, 0xe9, 0x39, 0x8d, 0x1b, 0xbf, 0x80,
0x3b, 0x7c, 0x0e, 0x77, 0xb4, 0x0b, 0x32, 0x33, 0x3a, 0xe0, 0xc0, 0x99,
0x37, 0x89, 0xad, 0x5e, 0x0f, 0x6e, 0x16, 0x00, 0x33, 0xdc, 0x84, 0x90,
0x16, 0x45, 0x04, 0x33, 0x96, 0xf7, 0x60, 0x61, 0x00, 0x4d, 0xec, 0xee,
0x77, 0x3a, 0x71, 0xd5, 0xed, 0x76, 0x24, 0xd8, 0x1d, 0x59, 0x5e, 0xa3,
0x77, 0x3e, 0x61, 0x18, 0xbe, 0x24, 0x5c, 0x93, 0x10, 0x2c, 0x40, 0x01,
0x13, 0x7d, 0x54, 0x97, 0x07, 0xf4, 0x03, 0x9a, 0x5f, 0xef, 0x5a, 0x65,
0x65, 0x65, 0xac, 0x58, 0xb1, 0x9c, 0x0a, 0x2b, 0x8b, 0x3b, 0x3d, 0xc2,
0xe4, 0xa9, 0x57, 0x70, 0xc6, 0xfa, 0xc9, 0xf4, 0x9e, 0xe3, 0xca, 0xde,
0xbb, 0xe8, 0x7f, 0xf2, 0x4f, 0x75, 0x18, 0xbd, 0x2a, 0xae, 0x16, 0x5e,
0x7a, 0x9a, 0xa1, 0xf7, 0x7e, 0x48, 0x20, 0x68, 0xea, 0xe3, 0x1a, 0x61,
0x20, 0xed, 0xea, 0x52, 0x5f, 0xdb, 0xb2, 0x20, 0x80, 0x0e, 0x71, 0x5f,
0xc7, 0x25, 0x66, 0xed, 0x8d, 0x86, 0x6d, 0x3c, 0x63, 0x47, 0x23, 0x18,
0xd7, 0x42, 0x98, 0x12, 0xa4, 0xa4, 0x14, 0x56, 0xe5, 0x7a, 0x6d, 0xc4,
0x9b, 0xe8, 0xa5, 0xcc, 0x19, 0x63, 0x49, 0x34, 0xcc, 0x8a, 0xba, 0x4a,
0x96, 0xd6, 0x84, 0xb1, 0x92, 0x57, 0xf0, 0x12, 0x7d, 0x4c, 0xb6, 0xbf,
0xc4, 0xe0, 0x77, 0x1f, 0x65, 0xe4, 0xa5, 0x7f, 0xc4, 0x08, 0x57, 0x62,
0x45, 0x97, 0x12, 0x68, 0xdc, 0x00, 0xd7, 0x4c, 0xba, 0xbe, 0x72, 0x59,
0xad, 0xab, 0xe7, 0xcf, 0x12, 0x6b, 0x6e, 0xd3, 0x1b, 0x99, 0x9a, 0x9d,
0x24, 0x8f, 0x30, 0x2b, 0x4a, 0xf4, 0x81, 0x68, 0x67, 0x0e, 0x93, 0x22,
0x62, 0x0f, 0xbe, 0x9d, 0x04, 0x1e, 0x88, 0x1f, 0xd8, 0xf2, 0x9a, 0x08,
0x06, 0xfe, 0x15, 0xa5, 0xaa, 0x11, 0x82, 0x52, 0x98, 0xe5, 0x4d, 0xa0,
0xdc, 0xb9, 0xd9, 0x4c, 0x43, 0x6a, 0x14, 0x94, 0xe7, 0x4b, 0xe9, 0x51,
0xf9, 0x0a, 0x35, 0xb6, 0x10, 0x6c, 0xdc, 0x48, 0xf9, 0xc6, 0x3b, 0x30,
0x82, 0x41, 0x56, 0x3d, 0x7a, 0x10, 0xe5, 0xe6, 0xf4, 0xac, 0xe3, 0x79,
0x80, 0x47, 0x76, 0x7a, 0x9a, 0xa8, 0x7f, 0x3e, 0xdb, 0xff, 0x2e, 0xda,
0xbc, 0x2a, 0xec, 0x39, 0x0f, 0x00, 0x85, 0xca, 0x08, 0x21, 0xff, 0x0b,
0xa5, 0x2e, 0xab, 0xb4, 0xfd, 0xbd, 0x45, 0xfc, 0x5f, 0x48, 0xff, 0x90,
0x59, 0xe6, 0x49, 0xef, 0xdf, 0x81, 0xed, 0x94, 0x20, 0xdc, 0xf4, 0x00,
0x46, 0xb4, 0x09, 0x19, 0x8a, 0x82, 0x52, 0xda, 0x30, 0x79, 0xe1, 0xcd,
0x19, 0x54, 0x20, 0x24, 0xca, 0x75, 0xb4, 0xb1, 0x7c, 0x38, 0xb4, 0x94,
0x3e, 0xde, 0xd7, 0x75, 0x85, 0xda, 0x4d, 0x3b, 0x08, 0x4c, 0x9e, 0x87,
0xcc, 0x14, 0x85, 0xcc, 0x0e, 0xbc, 0x8c, 0x9b, 0x1e, 0x06, 0xc5, 0x1b,
0xb1, 0xdd, 0xa7, 0x7e, 0x87, 0x22, 0x24, 0x1f, 0x40, 0xf4, 0xde, 0xf6,
0x7e, 0xff, 0xa1, 0xe9, 0x53, 0x02, 0x5e, 0x2c, 0xbd, 0x39, 0x4a, 0xbc,
0xa9, 0xab, 0x28, 0x67, 0x16, 0x3d, 0xa3, 0xf3, 0xd2, 0x65, 0xf1, 0xb3,
0x3a, 0xcf, 0xa6, 0x20, 0x97, 0x2f, 0x97, 0x8c, 0x96, 0xf2, 0xe5, 0x39,
0x69, 0x86, 0xfa, 0xe3, 0xac, 0xdc, 0xf1, 0x10, 0xa3, 0x3f, 0x79, 0x6b,
0x81, 0x79, 0x95, 0x9b, 0xc1, 0xcd, 0xc4, 0x01, 0x90, 0x86, 0xfc, 0x73,
0x4a, 0x20, 0xf9, 0x85, 0x28, 0xa5, 0x66, 0xed, 0x07, 0x80, 0x01, 0x8a,
0xf0, 0x72, 0x49, 0xf0, 0x5c, 0xbc, 0xe4, 0x20, 0xda, 0x94, 0xd6, 0xcf,
0x9a, 0x93, 0x9c, 0x0e, 0xe3, 0xab, 0xa0, 0x59, 0xb5, 0xd2, 0xcc, 0x4e,
0x8e, 0x32, 0x9a, 0xc8, 0x11, 0xf1, 0xcb, 0xcb, 0x2a, 0xaf, 0x22, 0x71,
0xb1, 0x1d, 0x85, 0x02, 0x2d, 0x34, 0xd9, 0xc9, 0xf7, 0xe7, 0x56, 0x93,
0x44, 0xf4, 0xee, 0xf6, 0xf6, 0x45, 0x07, 0x28, 0xd9, 0x17, 0x82, 0x33,
0x0b, 0x02, 0x64, 0x46, 0x01, 0x50, 0x99, 0x24, 0xb9, 0x44, 0x2f, 0x38,
0xa9, 0xf9, 0x15, 0x50, 0x05, 0x2b, 0xe0, 0xe9, 0x60, 0x69, 0x3c, 0xff,
0xbc, 0xe7, 0xd7, 0x78, 0xbc, 0xa7, 0x07, 0x63, 0xe5, 0x36, 0x96, 0x6d,
0xdb, 0xcd, 0xec, 0xd8, 0x55, 0xc6, 0x2f, 0x9d, 0x62, 0xf2, 0xf2, 0xbb,
0xfa, 0xfe, 0xaf, 0xf2, 0x7f, 0x5e, 0x96, 0xdc, 0xd4, 0x85, 0x7c, 0xfd,
0x7f, 0x0f, 0x4a, 0x63, 0xb2, 0x58, 0x14, 0x83, 0x14, 0xe1, 0x4c, 0x5d,
0xc2, 0x2c, 0x5f, 0x0d, 0xc0, 0x40, 0x67, 0x17, 0xc9, 0xa1, 0x5e, 0xa2,
0xcb, 0x9b, 0xa8, 0xa8, 0x89, 0x11, 0xa8, 0xa8, 0xc4, 0xb0, 0x02, 0x28,
0x5c, 0x1d, 0x60, 0x7a, 0x74, 0x84, 0xac, 0x11, 0x25, 0xb4, 0x6c, 0x03,
0x86, 0x17, 0x27, 0xb2, 0xbc, 0x79, 0xfe, 0x19, 0xad, 0x63, 0xdf, 0x67,
0x71, 0xd3, 0x49, 0xf0, 0x72, 0x28, 0x69, 0x22, 0x84, 0x81, 0xe3, 0xf7,
0x83, 0xf2, 0x1c, 0x50, 0x24, 0x6b, 0x77, 0x9f, 0xfe, 0xf2, 0x2f, 0x1d,
0x40, 0x21, 0x7a, 0x04, 0x8a, 0x42, 0xdc, 0xd9, 0x01, 0xbd, 0x0a, 0x32,
0x10, 0x63, 0xd9, 0xda, 0xd5, 0xa8, 0x75, 0xcd, 0x5c, 0xed, 0xee, 0x65,
0x78, 0x64, 0x86, 0x9a, 0xd8, 0x06, 0x7f, 0x66, 0x3b, 0x88, 0x36, 0x6f,
0x26, 0x50, 0xdf, 0x40, 0x76, 0xf6, 0x1c, 0xcb, 0x6e, 0xdb, 0x09, 0x40,
0x7a, 0x6c, 0x90, 0xec, 0xd4, 0x28, 0x0a, 0xb8, 0x70, 0xf0, 0x71, 0xa6,
0x07, 0x3a, 0x09, 0x46, 0xeb, 0x51, 0x80, 0x00, 0x72, 0x33, 0x3d, 0x64,
0x13, 0x3f, 0xca, 0x17, 0xf0, 0x83, 0xe8, 0x3a, 0x2a, 0x8d, 0x64, 0xb1,
0x28, 0xef, 0x0c, 0x25, 0x48, 0x0f, 0x1f, 0x45, 0xcf, 0x14, 0x20, 0x94,
0xc3, 0xd2, 0xa6, 0x9b, 0x58, 0xb9, 0x76, 0x29, 0xce, 0xc8, 0x45, 0x2a,
0x9b, 0x5a, 0x70, 0xa6, 0x27, 0x29, 0xab, 0x5d, 0xc1, 0xd2, 0x4f, 0x7c,
0x86, 0xe1, 0x1f, 0xbf, 0x0e, 0x80, 0xe7, 0x3a, 0xbc, 0xff, 0xf4, 0xd7,
0x79, 0xfd, 0xa1, 0x66, 0x26, 0xfe, 0xe7, 0xc7, 0x00, 0x54, 0x2c, 0x5b,
0x8d, 0xbe, 0x29, 0xa4, 0xfa, 0xc8, 0x0c, 0x1f, 0xc9, 0x7b, 0x3e, 0x55,
0x7b, 0x6f, 0xc7, 0x7f, 0xdc, 0xb0, 0xf7, 0x03, 0x63, 0x07, 0x5a, 0xbf,
0xa9, 0x04, 0xdf, 0x40, 0x70, 0x59, 0x28, 0x4e, 0x28, 0xb8, 0x0f, 0xc0,
0x08, 0xd4, 0x12, 0xa8, 0xdf, 0x8e, 0xb4, 0x2a, 0xf2, 0x35, 0x8b, 0x52,
0xfa, 0x49, 0x93, 0xc1, 0x9f, 0xf6, 0x32, 0xda, 0xdd, 0x45, 0xd5, 0xaa,
0x8d, 0x24, 0xfb, 0x2f, 0xf9, 0xea, 0xd4, 0xa6, 0x0b, 0xd0, 0x3b, 0x7e,
0xdb, 0xe7, 0x1f, 0x27, 0x12, 0x1c, 0xf3, 0xcd, 0x1f, 0xcb, 0x37, 0x72,
0x7f, 0x2c, 0xe9, 0xad, 0xe2, 0xe1, 0xd3, 0xce, 0x8d, 0x0a, 0xa0, 0x19,
0x39, 0xd8, 0x56, 0x3f, 0x55, 0x35, 0x36, 0xb1, 0xe6, 0x77, 0xbb, 0x32,
0xa3, 0xcf, 0xb5, 0x3e, 0x8c, 0xc7, 0x93, 0x80, 0x14, 0xd2, 0x22, 0x10,
0xdb, 0x8a, 0x19, 0xf9, 0xc8, 0x5c, 0x00, 0x17, 0xe5, 0xe5, 0xc0, 0x73,
0x98, 0x99, 0x9a, 0xe1, 0xcc, 0xf3, 0x4f, 0x33, 0x3d, 0x78, 0x85, 0x62,
0x82, 0xd5, 0x75, 0xb4, 0xdc, 0xfd, 0x39, 0x2a, 0xad, 0x4e, 0x72, 0x53,
0x5d, 0x79, 0xf3, 0xe3, 0x63, 0xe1, 0xa9, 0xc6, 0x75, 0x77, 0x5e, 0x4c,
0xfe, 0xbf, 0xbf, 0x62, 0x1a, 0x7e, 0xae, 0xad, 0xcd, 0xf0, 0xbc, 0xa3,
0x40, 0x08, 0xbd, 0x3b, 0xaf, 0xc2, 0xaa, 0x5a, 0x8f, 0xb4, 0x6b, 0x50,
0x80, 0xde, 0x91, 0x3d, 0x0f, 0x4f, 0x41, 0xef, 0x4f, 0xce, 0xd1, 0xd7,
0xfe, 0x3a, 0xb9, 0x74, 0x8a, 0xf2, 0x86, 0x46, 0x1a, 0x36, 0xde, 0x4a,
0x5d, 0x43, 0x1a, 0x4f, 0xd7, 0xfb, 0x3c, 0x5d, 0x6e, 0x2e, 0xf3, 0x5b,
0xf5, 0xf7, 0x9f, 0x1d, 0xf9, 0xd5, 0xbd, 0x23, 0xfb, 0x97, 0x96, 0x72,
0x51, 0x1d, 0xde, 0x0f, 0xea, 0x0f, 0x00, 0x01, 0x80, 0x30, 0x31, 0x82,
0x75, 0xc8, 0xb2, 0x25, 0x48, 0xab, 0x5a, 0xbf, 0x13, 0xc0, 0x9b, 0xdb,
0xf0, 0x54, 0x16, 0x77, 0x76, 0x04, 0x2f, 0x9b, 0x28, 0xfa, 0xad, 0xc2,
0xbe, 0x9a, 0x5d, 0xa7, 0xbe, 0xf6, 0x2b, 0x7f, 0xc9, 0x97, 0x67, 0xe2,
0xc0, 0xa6, 0x95, 0xae, 0xb4, 0xbe, 0xaf, 0x94, 0x6a, 0x05, 0xe4, 0xa2,
0x0c, 0x80, 0xe3, 0x29, 0x8e, 0x92, 0x95, 0x5f, 0xa8, 0xdd, 0xd3, 0xde,
0xf5, 0xeb, 0x78, 0x4b, 0xb9, 0x90, 0x17, 0x84, 0x11, 0x77, 0x5b, 0xf7,
0x48, 0xa5, 0x1e, 0x52, 0xd0, 0x0c, 0x84, 0x00, 0x7b, 0x2e, 0x94, 0x03,
0x8c, 0x03, 0x7d, 0x0a, 0x5e, 0xac, 0xdd, 0xd5, 0xb1, 0x4f, 0xd7, 0xd9,
0x87, 0xe4, 0x7f, 0x01, 0x9c, 0x0b, 0xc5, 0xc1, 0xee, 0xb9, 0xae, 0x42,
0x00, 0x00, 0x00, 0x00, 0x49, 0x45, 0x4e, 0x44, 0xae, 0x42, 0x60, 0x82
])

def front():
    global content
    content = "<html><body><center><h2>Hello friend. Have you seen this guy?</h2>\n<br><br><img src=\"/image.png\"><br><br><form action=/ method=post><input type=radio name=q1 value=yes>Why yes I have<br><input type=radio name=q1 value=no>No, who's he?<br><input type=radio name=q1 value=who>Canada<hr width='20%%'><input type=submit></form></center></body></html>"

def points():
    global content
    content = "<html><body><center><h2>Correct!</h2>\n<br><br><a href='http://monkey-project.com'>Visit him.</a></center></body></html>"

def wrong():
    global content
    content = "<html><body><center><h2>I'm a sad puppy.</h2>\n</center></body></html>"

def listf(vhost, url, get, get_len, post, post_len, header):
    global content
    global image
    ret = {}
    if url == '/image.png':
        ret['content'] = image
        ret['clen'] = len(ret['content'])
        ret['return'] = 1
        return ret
    if post is None:
        front()
    elif 'q1=who' in post or 'q1=yes' in post:
        points()
    else:
        wrong()

    ret['content'] = content
    ret['clen'] = len(ret['content'])
    ret['return'] = 1

    return ret

monkey.init(None, 0, 0, None)
monkey.set_callback('data', listf)
monkey.start()
raw_input()
monkey.stop()