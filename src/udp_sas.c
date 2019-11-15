
#define _GNU_SOURCE 1 // needed for struct in6_pktinfo
#if !defined(__Windows__)
#include <netinet/in.h>
#include <sys/socket.h>
#include <netinet/ip.h>
#include <string.h>
// constants to be exported in rust
int udp_sas_IP_PKTINFO = IP_PKTINFO;
int udp_sas_IPV6_RECVPKTINFO = IPV6_RECVPKTINFO;
#else
#include <Winsock2.h>
#include <Ws2tcpip.h>
#include <Mswsock.h>
// constants to be exported in rust
int udp_sas_IP_PKTINFO = IP_PKTINFO;
int udp_sas_IPV6_RECVPKTINFO = IPV6_PKTINFO;
#endif

#if !defined(__Windows__)
ssize_t udp_sas_recv(
	int sock,
#else
int udp_sas_recv(
	int sock,
#endif
	void *buf, size_t buf_len, int flags,
	struct sockaddr *src, socklen_t src_len,
	struct sockaddr *dst, socklen_t dst_len)
{
#if !defined(__Windows__)
	struct iovec iov = {
		.iov_base = buf,
		.iov_len = buf_len};
	char control[256];
	struct msghdr msg = {
		.msg_name = src,
		.msg_namelen = src_len,
		.msg_iov = &iov,
		.msg_iovlen = 1,
		.msg_control = control,
		.msg_controllen = sizeof(control),
		.msg_flags = 0,
	};
#else
	WSABUF iov;
	iov.buf = buf;
	iov.len = buf_len;
	char ControlBuffer[1024];
	WSAMSG msg;
	GUID WSARecvMsg_GUID = WSAID_WSARECVMSG;
	LPFN_WSARECVMSG WSARecvMsg;
	DWORD ncounter = 0;
	int nResult;
	flags = 0;
#endif
	memset(src, 0, src_len);
	memset(dst, 0, dst_len);

#if !defined(__Windows__)
	ssize_t nb = recvmsg(sock, &msg, flags);
	if (nb >= 0)
#else
	nResult = WSAIoctl(sock, SIO_GET_EXTENSION_FUNCTION_POINTER,
					   &WSARecvMsg_GUID, sizeof WSARecvMsg_GUID,
					   &WSARecvMsg, sizeof WSARecvMsg,
					   &ncounter, NULL, NULL);
	if (nResult == 0)
	{
		msg.name = src;
		msg.namelen = src_len;
		msg.lpBuffers = &iov;
		msg.dwBufferCount = 1;
		msg.Control.buf = ControlBuffer;
		msg.Control.len = sizeof(ControlBuffer);
		msg.dwFlags = 0;
		nResult = WSARecvMsg(sock, &msg, &ncounter, NULL, NULL);
	}
	else
	{
		return nResult;
	}
	if (nResult == 0)
#endif
	{
		// parse the ancillary data
#if !defined(__Windows__)
		struct cmsghdr *cmsg;
		for (cmsg = CMSG_FIRSTHDR(&msg); cmsg != 0; cmsg = CMSG_NXTHDR(&msg, cmsg))
#else
		LPWSACMSGHDR cmsg;
		for (cmsg = WSA_CMSG_FIRSTHDR(&msg); cmsg != 0; cmsg = WSA_CMSG_NXTHDR(&msg, cmsg))
#endif
		{
			// IPv4 destination (IP_PKTINFO)
			// NOTE: may also be present for v4-mapped addresses in IPv6
			if (cmsg->cmsg_level == IPPROTO_IP && cmsg->cmsg_type == IP_PKTINFO && dst_len >= sizeof(struct sockaddr_in))
			{
#if !defined(__Windows__)
				struct in_pktinfo *info = (struct in_pktinfo *)CMSG_DATA(cmsg);
#else
				struct in_pktinfo *info = (struct in_pktinfo *)WSA_CMSG_DATA(cmsg);
#endif
				struct sockaddr_in *sa = (struct sockaddr_in *)dst;
				sa->sin_family = AF_INET;
				sa->sin_port = 0; // not provided by the posix api
#if !defined(__Windows__)
				sa->sin_addr = info->ipi_spec_dst;
#else
				sa->sin_addr = info->ipi_addr;
#endif
			}
			// IPv6 destination (IPV6_RECVPKTINFO)
			else if (cmsg->cmsg_level == IPPROTO_IPV6 && cmsg->cmsg_type == IPV6_PKTINFO && dst_len >= sizeof(struct sockaddr_in6))
			{
#if !defined(__Windows__)
				struct in6_pktinfo *info = (struct in6_pktinfo *)CMSG_DATA(cmsg);
#else
				struct in6_pktinfo *info = (struct in6_pktinfo *)WSA_CMSG_DATA(cmsg);

#endif
				struct sockaddr_in6 *sa = (struct sockaddr_in6 *)dst;
				sa->sin6_family = AF_INET6;
				sa->sin6_port = 0; // not provided by the posix api
#if !defined(__Windows__)
				sa->sin6_addr = info->ipi6_addr;
				sa->sin6_flowinfo = 0;
				sa->sin6_scope_id = 0;
#else
				sa->sin6_addr = info->ipi6_addr;
				sa->sin6_scope_id = info->ipi6_ifindex;
#endif
			}
		}
	}
#if !defined(__Windows__)
	return nb;
#else
	if (nResult == 0)
	{
		return ncounter;
	}
	else
	{
		return -1;
	}
#endif
}

#if !defined(__Windows__)
ssize_t udp_sas_send(
	int sock,
#else
int udp_sas_send(
	SOCKET sock,
#endif
	void *buf, size_t buf_len, int flags,
	struct sockaddr *src, socklen_t src_len,
	struct sockaddr *dst, socklen_t dst_len)
{
#if !defined(__Windows__)
#else
#endif
#if !defined(__Windows__)
	struct iovec iov = {
		.iov_base = buf,
		.iov_len = buf_len};
	char control[256];
	struct msghdr msg = {
		.msg_name = dst,
		.msg_namelen = dst_len,
		.msg_iov = &iov,
		.msg_iovlen = 1,
		.msg_control = control,
		.msg_controllen = sizeof(control),
		.msg_flags = 0,
	};
#else
	WSAMSG msg;
	WSABUF iov;
	char ControlBuffer[1024];
	GUID WSASendMsg_GUID = WSAID_WSASENDMSG;
	LPFN_WSASENDMSG WSASendMsg;
	DWORD ncounter = 0;
	int nResult;
	int sum;
	nResult = WSAIoctl(sock, SIO_GET_EXTENSION_FUNCTION_POINTER,
					   &WSASendMsg_GUID, sizeof WSASendMsg_GUID,
					   &WSASendMsg, sizeof WSASendMsg,
					   &ncounter, NULL, NULL);
	if (nResult == 0)
	{
		msg.name = dst;
		msg.namelen = dst_len;
		iov.buf = buf;
		iov.len = buf_len;
		msg.lpBuffers = &iov;
		msg.dwBufferCount = 1;
		memset(ControlBuffer, 0, sizeof(ControlBuffer));
		msg.Control.buf = ControlBuffer;
		msg.Control.len = sizeof(ControlBuffer);
		msg.dwFlags = 0;
	}
	else
	{
		return nResult;
	}
#endif
	// add ancillary data
	//
	struct sockaddr_in *sa4 = (struct sockaddr_in *)src;
	struct sockaddr_in6 *sa6 = (struct sockaddr_in6 *)src;
#if !defined(__Windows__)
	struct cmsghdr *cmsg = CMSG_FIRSTHDR(&msg);
#else
	LPWSACMSGHDR cmsg = WSA_CMSG_FIRSTHDR(&msg);
	sum = 0;
#endif
	// IPv4 src address
	if ((src_len >= sizeof(struct sockaddr_in)) && (sa4->sin_family == AF_INET))
	{
		cmsg->cmsg_level = IPPROTO_IP;
		cmsg->cmsg_type = IP_PKTINFO;
#if !defined(__Windows__)
		struct in_pktinfo *info = (struct in_pktinfo *)CMSG_DATA(cmsg);
		memset(info, 0, sizeof(*info));
		info->ipi_spec_dst = sa4->sin_addr;
		cmsg->cmsg_len = CMSG_LEN(sizeof(*info));
#else
		struct in_pktinfo *info = (struct in_pktinfo *)WSA_CMSG_DATA(cmsg);
		memset(info, 0, sizeof(struct in_pktinfo));
		info->ipi_addr = sa4->sin_addr;
		info->ipi_ifindex = 1;
		cmsg->cmsg_len = WSA_CMSG_LEN(sizeof(struct in_pktinfo));
		sum += WSA_CMSG_SPACE(sizeof(struct in_pktinfo));
#endif
	}
	// IPv6 src address
	else if ((src_len >= sizeof(struct sockaddr_in6)) && (sa6->sin6_family == AF_INET6))
	{
		cmsg->cmsg_level = IPPROTO_IPV6;
		cmsg->cmsg_type = IPV6_PKTINFO;
#if !defined(__Windows__)
		struct in6_pktinfo *info = (struct in6_pktinfo *)CMSG_DATA(cmsg);
		memset(info, 0, sizeof(*info));
		info->ipi6_addr = sa6->sin6_addr;
		cmsg->cmsg_len = CMSG_LEN(sizeof(*info));
#else
		struct in6_pktinfo *info = (struct in6_pktinfo *)WSA_CMSG_DATA(cmsg);
		memset(info, 0, sizeof(struct in6_pktinfo));
		info->ipi6_addr = sa6->sin6_addr;
		cmsg->cmsg_len = WSA_CMSG_LEN(sizeof(struct in6_pktinfo));
		sum += WSA_CMSG_SPACE(sizeof(struct in6_pktinfo));
#endif
	}
	// no info
	else
	{
		cmsg->cmsg_len = 0;
	}

#if !defined(__Windows__)
	msg.msg_controllen = cmsg->cmsg_len;
	return sendmsg(sock, &msg, flags);
#else
	msg.Control.len = sum;

	int ret;
	ret = WSASendMsg(sock, &msg, flags, &ncounter, NULL, NULL);
	if (ret == 0)
	{
		return ncounter;
	}
	else
	{
		return -1;
	}
#endif
}