# cudy-bdinfo-decrypt

Decrypts the bdinfo partition of cudy routers.

## Format

| Offset | Length | Description |
| ------ | ------ | ----------- |
| 0x00   | 0x4    | Version     |
| 0x04   | 0xDD7C | Data        |

### Version

Big-Endian encoded bdinfo revision. Currently only version 1 is known to be supported.

### Data

DES encrypted data

Data is stored as key-value pairs in the format `key = value` seperated by the line-feed character.

End of data is indicated by the line `BDINFO_END`.
