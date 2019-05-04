/*
 * This software is in the public domain under CC0 1.0 Universal plus a
 * Grant of Patent License.
 *
 * To the extent possible under law, the author(s) have dedicated all
 * copyright and related and neighboring rights to this software to the
 * public domain worldwide. This software is distributed without any
 * warranty.
 *
 * You should have received a copy of the CC0 Public Domain Dedication
 * along with this software (see the LICENSE.md file). If not, see
 * <http://creativecommons.org/publicdomain/zero/1.0/>.
 */
package org.moqui.sftp

import groovy.transform.CompileStatic
import net.schmizz.sshj.SSHClient
import net.schmizz.sshj.sftp.FileAttributes
import net.schmizz.sshj.sftp.OpenMode
import net.schmizz.sshj.sftp.RemoteFile
import net.schmizz.sshj.sftp.RemoteResourceInfo
import net.schmizz.sshj.sftp.SFTPClient
import net.schmizz.sshj.transport.verification.PromiscuousVerifier
import net.schmizz.sshj.userauth.UserAuthException
import net.schmizz.sshj.userauth.keyprovider.KeyPairWrapper
import net.schmizz.sshj.userauth.keyprovider.KeyProvider
import net.schmizz.sshj.userauth.keyprovider.PKCS8KeyFile
import net.schmizz.sshj.xfer.InMemorySourceFile
import org.moqui.util.ObjectUtilities
import org.slf4j.Logger
import org.slf4j.LoggerFactory

import java.nio.charset.Charset
import java.nio.charset.StandardCharsets
import java.security.PrivateKey
import java.security.PublicKey

/** Single thread SFTP Client utility class
 *
 * SftpClient client = new SftpClient(host, port, username).password(password).connect()
 * try {
 *     // do some SFTP stuff
 * } finally {
 *     client.close()
 * }
 */
@CompileStatic
class SftpClient implements Closeable, AutoCloseable {
    private final static Logger logger = LoggerFactory.getLogger(SftpClient.class)

    // see https://www.adminsub.net/tcp-udp-port-finder/sftp
    public final static int SSH_PORT = 22, SFTP_PORT = 115

    private SFTPClient sftpClient
    private SSHClient sshClient
    private String host, username, password = null
    private int port = SFTP_PORT
    private ArrayList<KeyProvider> keyProviders = null
    private boolean preserveAttributes = true

    SftpClient(String host, String username, int port = SFTP_PORT) {
        int hostColonIdx = host.indexOf(":")
        if (hostColonIdx > 0) {
            this.host = host.substring(0, hostColonIdx)
            this.port = host.substring(hostColonIdx + 1) as int
        } else {
            this.host = host
            this.port = port
        }
        this.username = username
    }

    /** Authenticate with password */
    SftpClient password(String pw) { password = pw; return this }

    /** Authenticate with public key using public key and private key from Java security objects; may be called multiple times */
    SftpClient publicKey(PrivateKey privateKey, PublicKey publicKey) {
        if (keyProviders == null) keyProviders = new ArrayList<>()
        keyProviders.add(new KeyPairWrapper(publicKey, privateKey))
        return this
    }
    /** Authenticate with public key using public key and private key (PEM base64-encoded PKCS #8, same as OpenSSH) Strings; may be called multiple times */
    SftpClient publicKeyPkcs8(String privateKey, String publicKey) {
        if (keyProviders == null) keyProviders = new ArrayList<>()
        PKCS8KeyFile keyFile = new PKCS8KeyFile()
        keyFile.init(privateKey, publicKey)
        keyProviders.add(keyFile)
        return this
    }
    /** Authenticate with public key using SSHJ KeyProvider(s); this relies on a SSHJ so best to avoid using directly in case implementation changes */
    SftpClient publicKey(KeyProvider... providers) {
        if (keyProviders == null) keyProviders = new ArrayList<>()
        keyProviders.addAll(providers)
        return this
    }

    /** Workaround for SSHJ behavior of set file attributes after put/upload, set to false to not set file attributes after put/upload */
    SftpClient preserveAttributes(boolean pa) { preserveAttributes = pa; return this }

    /** Connect to SFTP host, authenticate, and init SFTP client */
    SftpClient connect() throws IOException {
        if (!host || !username) throw new IllegalStateException("Host or username not specified, cannot connect to ${username}@${host}:${port}")
        if (!password && !keyProviders) throw new IllegalStateException("No password or KeyProvider specified, cannot connect to ${username}@${host}:${port}")

        sshClient = new SSHClient()
        // TODO: consider some sort of known hosts verifier, though best not to rely on or even use the host OS known_hosts
        sshClient.addHostKeyVerifier(new PromiscuousVerifier())
        sshClient.connect(host, port)
        // authenticate
        try {
            if (password) {
                sshClient.authPassword(username, password)
            } else {
                sshClient.authPublickey(username, keyProviders)
            }
        } catch (UserAuthException e) {
            logger.error("Authentication by ${password ? 'password' : 'public key'} failed for ${username}@${host}:${port}", e)
            try { sshClient.close() }
            catch (Throwable ct) { logger.error("Error closing SSHClient", ct) }
            throw e
        } catch (Throwable t) {
            logger.error("Transport or other error authenticating to SFTP server for ${username}@${host}:${port}", t)
            try { sshClient.close() }
            catch (Throwable ct) { logger.error("Error closing SSHClient", ct) }
            throw t
        }
        // init SFTPClient
        try {
            sftpClient = sshClient.newSFTPClient()
            if (!preserveAttributes) sftpClient.getFileTransfer().setPreserveAttributes(false)
        } catch (Throwable t) {
            logger.error("Error initializing SFTPClient for ${username}@${host}:${port}", t)
            try { sshClient.close() }
            catch (Throwable ct) { logger.error("Error closing SSHClient", ct) }
            throw t
        }

        return this
    }

    /** Get internal SFTPClient instance for SSHJ; best to avoid using directly in case implementation changes */
    SFTPClient getInternalClient() { return sftpClient }

    /** Get list of files in remote directory specified by path (only files, no subdirectories) */
    ArrayList<String> lsFiles(String path) {
        List<RemoteResourceInfo> resourceList = sftpClient.ls(path)
        ArrayList<String> fileNames = new ArrayList<>(resourceList.size())
        for (RemoteResourceInfo rri in resourceList) if (rri.isRegularFile()) fileNames.add(rri.getName())
        return fileNames
    }
    /** Get list of all directory entries with details in a map containing:
     *     name, path, isFile (Boolean; false for directory), size (Long), lastAccess (Long), lastModified (Long) */
    ArrayList<Map<String, Object>> ls(String path) {
        List<RemoteResourceInfo> resourceList = sftpClient.ls(path)
        ArrayList<Map<String, Object>> fileInfoList = new ArrayList<>(resourceList.size())
        for (RemoteResourceInfo rri in resourceList) {
            if (rri.isRegularFile() || rri.isDirectory()) {
                FileAttributes attrs = rri.getAttributes()
                fileInfoList.add([name:rri.getName(), path:rri.getPath(), isFile:rri.isRegularFile(), size:attrs.getSize(),
                        lastAccess:attrs.getAtime(), lastModified:attrs.getMtime()] as Map<String, Object>)
            }
        }
        return fileInfoList
    }

    /** Open InputStream for file; stream must be closed, best done in a try finally block */
    InputStream openStream(String path) {
        Set modeSet = new HashSet(); modeSet.add(OpenMode.READ)
        RemoteFile rf = sftpClient.open(path, modeSet)
        RemoteFile.RemoteFileInputStream is = RemoteFile.RemoteFileInputStream.newInstance(rf)
        return is
    }
    byte[] getBinary(String path) {
        Set modeSet = new HashSet(); modeSet.add(OpenMode.READ)
        RemoteFile rf = sftpClient.open(path, modeSet)
        try {
            RemoteFile.RemoteFileInputStream is = RemoteFile.RemoteFileInputStream.newInstance(rf)
            try {
                ByteArrayOutputStream baos = new ByteArrayOutputStream()
                ObjectUtilities.copyStream(is, baos)
                return baos.toByteArray()
            } finally {
                is.close()
            }
        } finally {
            rf.close()
        }
    }
    /** Get remote file as a String, decoded using specified Charset (defaults to UTF-8) which is the expected Charset for the remote file */
    String getText(String path, Charset charset = StandardCharsets.UTF_8) {
        Set modeSet = new HashSet(); modeSet.add(OpenMode.READ)
        RemoteFile rf = sftpClient.open(path, modeSet)
        try {
            RemoteFile.RemoteFileInputStream is = RemoteFile.RemoteFileInputStream.newInstance(rf)
            try {
                return ObjectUtilities.getStreamText(is, charset)
            } finally {
                is.close()
            }
        } finally {
            rf.close()
        }
    }

    /** Put a file from a text String; path may be to a target directory or file path, if directory filename is used as remote
     *     filename in path directory; the charset is used for the binary encoded, ie the charset to send to remote server */
    SftpClient put(String path, String filename, String fileText, Charset charset = StandardCharsets.UTF_8) {
        ByteSourceFile bsf = new ByteSourceFile(filename, fileText, charset)
        sftpClient.put(bsf, path)
        return this
    }
    /** Put a file from a byte arry; path may be to a target directory or file path, if directory filename is used as remote filename in path directory */
    SftpClient put(String path, String filename, byte[] fileData) {
        ByteSourceFile bsf = new ByteSourceFile(filename, fileData)
        sftpClient.put(bsf, path)
        return this
    }
    /** Put a file from an InputStream; path may be to a target directory or file path, if directory filename is used as remote filename in path directory */
    SftpClient put(String path, String filename, InputStream is) {
        StreamSourceFile ssf = new StreamSourceFile(filename, is)
        sftpClient.put(ssf, path)
        return this
    }

    /** Move a file at a path to a different directory (created if missing); returns new file path */
    String moveFile(String filePath, String destDirPath, boolean createDir = true) {
        if(createDir) sftpClient.mkdirs(destDirPath)

        // NOTE: detect Windows paths with backslash? is it needed?
        int lastSepIdx = filePath.lastIndexOf("/")
        String fileName = lastSepIdx >= 0 ? filePath.substring(lastSepIdx + 1) : filePath

        if (!destDirPath.endsWith('/')) destDirPath += '/'
        String newFilePath = destDirPath + fileName

        sftpClient.rename(filePath, newFilePath)
        return newFilePath
    }
    /** Rename a file in the same directory */
    String renameFile(String filePath, String newFileName) {
        // NOTE: detect Windows paths with backslash? is it needed?
        int lastSepIdx = filePath.lastIndexOf("/")
        // get dir path by substring on last separator index plus 1 to include separator
        String dirPath = lastSepIdx > 0 ? filePath.substring(0, lastSepIdx + 1) : ""
        String newFilePath = dirPath + newFileName

        sftpClient.rename(filePath, newFilePath)
        return newFilePath
    }
    /** Rename or move file or directory by full source and destination paths */
    String rename(String filePath, String newFilePath) {
        sftpClient.rename(filePath, newFilePath)
        return newFilePath
    }

    /** Remove (delete) file at specified path on remote server */
    SftpClient rm(String path) {
        sftpClient.rm(path)
        return this
    }

    /** Call to close connection, clean up resources, etc; best called in a try finally block */
    @Override
    void close() throws IOException {
        // TODO: doesn't look like close on SFTPClient is required but watch for issues (if needed close in try block with finally to close SSHClient)
        if (sshClient != null && sshClient.isConnected()) sshClient.close()
    }

    @Override
    void finalize() throws Throwable {
        try {
            if (sshClient != null && sshClient.isConnected()) {
                logger.error("SftpClient not closed for host ${username}@${host}:${port}, caught in finalize()")
                this.close()
            }
        } catch (Exception e) {
            logger.error("Error closing connection to ${username}@${host}:${port} in finalize SftpClient", e)
        }

        super.finalize()
    }

    static class StreamSourceFile extends InMemorySourceFile {
        private String name
        private InputStream inputStream
        private long length

        StreamSourceFile(String name, InputStream inputStream, long length = 0) {
            this.name = name; this.inputStream = inputStream; this.length = length }

        @Override String getName() { return name }
        @Override long getLength() { return length }
        @Override InputStream getInputStream() throws IOException { return inputStream }
    }
    static class ByteSourceFile extends InMemorySourceFile {
        private String name
        private byte[] data

        ByteSourceFile(String name, byte[] dataBytes) { this.name = name; this.data = dataBytes }
        ByteSourceFile(String name, String dataString, Charset charset = StandardCharsets.UTF_8) {
            this.name = name
            this.data = dataString.getBytes(charset)
        }

        @Override String getName() { return name }
        @Override long getLength() { return data.length }
        @Override InputStream getInputStream() throws IOException { return new ByteArrayInputStream(data) }
    }
}
