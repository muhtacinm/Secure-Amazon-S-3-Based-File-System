# Secure S3FS 

Secure S3FS implements a layer of encryption using Openssl RC4 to an S3 bucket via FUSE. 

## Pre-Requisites

Ensure existing packages are updated. 

```bash
sudo apt-get update
```

## Installation


```bash
1. git clone https://github.com/s3fs-fuse/s3fs-fuse.git
2. cp projectfolder/fdcache_entity.cpp ~/s3fs-secure/src
4. cd s3fs-secure
5. ./configure
6. make 
7. sudo make install
```

## Usage

s3fs supports the standard
[AWS credentials file](https://docs.aws.amazon.com/cli/latest/userguide/cli-config-files.html)
stored in `${HOME}/.aws/credentials`.  Alternatively, s3fs supports a custom passwd file.

The default location for the s3fs password file can be created:

* using a `.passwd-s3fs` file in the users home directory (i.e. `${HOME}/.passwd-s3fs`)
* using the system-wide `/etc/passwd-s3fs` file

Enter your credentials in a file `${HOME}/.passwd-s3fs` and set
owner-only permissions:

```
echo ACCESS_KEY_ID:SECRET_ACCESS_KEY > ${HOME}/.passwd-s3fs
chmod 600 ${HOME}/.passwd-s3fs
```

Create a key in file `${HOME}/pass.txt` to use for encryption and decryption

```
echo KEY > ${HOME}/pass.txt
```

Run s3fs with an existing bucket `mybucket` and directory `/path/to/mountpoint`:

```
s3fs mybucket /path/to/mountpoint -o passwd_file=${HOME}/.passwd-s3fs
```

If you encounter any errors, enable debug output:

```
s3fs mybucket /path/to/mountpoint -o passwd_file=${HOME}/.passwd-s3fs -o dbglevel=info -f -o curldbg
```


Note: You may also want to create the global credential file first

```
echo ACCESS_KEY_ID:SECRET_ACCESS_KEY > /etc/passwd-s3fs
chmod 600 /etc/passwd-s3fs
```

## Standalone RC4

A standalone RC4 program compatible with OpenSSL with salt and nosalt options. 

## Pre-Requisites


```bash
sudo apt-get install libssl-dev
export LD_LIBRARY_PATH=path_to_openssl:$LD_LIBRARY_PATH
```

## Compilation 

```bash
gcc rc4stand.c -lcrypto -o rc4 
```

## Usage

```bash
./rc4 -e|-d -k key -in inputfile -out outputfile -salt|-nosalt
```

## FAQ

* [FAQ wiki page](https://github.com/s3fs-fuse/s3fs-fuse/wiki/FAQ)
* [s3fs on Stack Overflow](https://stackoverflow.com/questions/tagged/s3fs)
* [s3fs on Server Fault](https://serverfault.com/questions/tagged/s3fs)

