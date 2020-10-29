/*
 * INET		An implementation of the TCP/IP protocol suite for the LINUX
 *		operating system.  INET is implemented using the  BSD Socket
 *		interface as the means of communication with the user level.
 *
 *		Implementation of the Transmission Control Protocol(TCP).
 *
 * Authors:	Ross Biro
 *		Fred N. van Kempen, <waltje@uWalt.NL.Mugnet.ORG>
 *		Mark Evans, <evansmp@uhura.aston.ac.uk>
 *		Corey Minyard <wf-rch!minyard@relay.EU.net>
 *		Florian La Roche, <flla@stud.uni-sb.de>
 *		Charles Hedrick, <hedrick@klinzhai.rutgers.edu>
 *		Linus Torvalds, <torvalds@cs.helsinki.fi>
 *		Alan Cox, <gw4pts@gw4pts.ampr.org>
 *		Matthew Dillon, <dillon@apollo.west.oic.com>
 *		Arnt Gulbrandsen, <agulbra@nvg.unit.no>
 *		Jorge Cwik, <jorge@laser.satlink.net>
 */

#include <linux/module.h>
#include <linux/gfp.h>
#include <net/tcp.h>

int sysctl_tcp_syn_retries __read_mostly = TCP_SYN_RETRIES;
int sysctl_tcp_synack_retries __read_mostly = TCP_SYNACK_RETRIES;
int sysctl_tcp_keepalive_time __read_mostly = TCP_KEEPALIVE_TIME;
int sysctl_tcp_keepalive_probes __read_mostly = TCP_KEEPALIVE_PROBES;
int sysctl_tcp_keepalive_intvl __read_mostly = TCP_KEEPALIVE_INTVL;
int sysctl_tcp_retries1 __read_mostly = TCP_RETR1;
int sysctl_tcp_retries2 __read_mostly = TCP_RETR2;
int sysctl_tcp_orphan_retries __read_mostly;
int sysctl_tcp_thin_linear_timeouts __read_mostly;

static void tcp_write_timer(unsigned long);
static void tcp_delack_timer(unsigned long);
static void tcp_keepalive_timer (unsigned long data);

void tcp_init_xmit_timers(struct sock *sk)
{
	inet_csk_init_xmit_timers(sk, &tcp_write_timer, &tcp_delack_timer,
				  &tcp_keepalive_timer);
}

EXPORT_SYMBOL(tcp_init_xmit_timers);

//�ر��׽��ֲ��ͷ���Դ
static void tcp_write_err(struct sock *sk)
{
	sk->sk_err = sk->sk_err_soft ? : ETIMEDOUT;
	sk->sk_error_report(sk);

	tcp_done(sk);
	NET_INC_STATS_BH(sock_net(sk), LINUX_MIB_TCPABORTONTIMEOUT);
}

/* Do not allow orphaned sockets to eat all our resources.
 * This is direct violation of TCP specs, but it is required
 * to prevent DoS attacks. It is called when a retransmission timeout
 * or zero probe timeout occurs on orphaned socket.
 *
 * Criteria is still not confirmed experimentally and may change.
 * We kill the socket, if:
 * 1. If number of orphaned sockets exceeds an administratively configured
 *    limit.
 * 2. If we have strong memory pressure.
 */
static int tcp_out_of_resources(struct sock *sk, int do_reset)
{
	struct tcp_sock *tp = tcp_sk(sk);
	int shift = 0;

	/* If peer does not open window for long time, or did not transmit
	 * anything for long time, penalize it. */
	if ((s32)(tcp_time_stamp - tp->lsndtime) > 2*TCP_RTO_MAX || !do_reset)
		shift++;

	/* If some dubious ICMP arrived, penalize even more. */
	if (sk->sk_err_soft)
		shift++;

	if (tcp_too_many_orphans(sk, shift)) {
		if (net_ratelimit())
			printk(KERN_INFO "Out of socket memory\n");

		/* Catch exceptional cases, when connection requires reset.
		 *      1. Last segment was sent recently. */
		if ((s32)(tcp_time_stamp - tp->lsndtime) <= TCP_TIMEWAIT_LEN ||
		    /*  2. Window is closed. */
		    (!tp->snd_wnd && !tp->packets_out))
			do_reset = 1;
		if (do_reset)
			tcp_send_active_reset(sk, GFP_ATOMIC);
		tcp_done(sk);
		NET_INC_STATS_BH(sock_net(sk), LINUX_MIB_TCPABORTONMEMORY);
		return 1;
	}
	return 0;
}

/* Calculate maximal number or retries on an orphaned socket.
 */
static int tcp_orphan_retries(struct sock *sk, int alive)
{
	int retries = sysctl_tcp_orphan_retries; /* May be zero. */

	/* We know from an ICMP that something is wrong. */
	if (sk->sk_err_soft && !alive)
		retries = 0;

	/* However, if socket sent something recently, select some safe
	 * number of retries. 8 corresponds to >100 seconds with minimal
	 * RTO of 200msec. */
	if (retries == 0 && alive)
		retries = 8;
	return retries;
}

// tcp_mtu_probing
static void tcp_mtu_probing(struct inet_connection_sock *icsk, struct sock *sk)
{
	/* Black hole detection */
	if (sysctl_tcp_mtu_probing) {
		if (!icsk->icsk_mtup.enabled) {
			icsk->icsk_mtup.enabled = 1;
			tcp_sync_mss(sk, icsk->icsk_pmtu_cookie);
		} else {
			struct tcp_sock *tp = tcp_sk(sk);
			int mss;

			mss = tcp_mtu_to_mss(sk, icsk->icsk_mtup.search_low) >> 1;
			mss = min(sysctl_tcp_base_mss, mss);
			mss = max(mss, 68 - tp->tcp_header_len);
			icsk->icsk_mtup.search_low = tcp_mss_to_mtu(sk, mss);
			tcp_sync_mss(sk, icsk->icsk_pmtu_cookie);
		}
	}
}

/* This function calculates a "timeout" which is equivalent to the timeout of a
 * TCP connection after "boundary" unsuccessful, exponentially backed-off
 * retransmissions with an initial RTO of TCP_RTO_MIN or TCP_TIMEOUT_INIT if
 * syn_set flag is set.
 */
static bool retransmits_timed_out(struct sock *sk,
				  unsigned int boundary,
				  bool syn_set)
{
	unsigned int timeout, linear_backoff_thresh;
	unsigned int start_ts;
	unsigned int rto_base = syn_set ? TCP_TIMEOUT_INIT : TCP_RTO_MIN;

	if (!inet_csk(sk)->icsk_retransmits)
		return false;

	if (unlikely(!tcp_sk(sk)->retrans_stamp))
		start_ts = TCP_SKB_CB(tcp_write_queue_head(sk))->when;
	else
		start_ts = tcp_sk(sk)->retrans_stamp;

	linear_backoff_thresh = ilog2(TCP_RTO_MAX/rto_base);

	if (boundary <= linear_backoff_thresh)
		timeout = ((2 << boundary) - 1) * rto_base;
	else
		timeout = ((2 << linear_backoff_thresh) - 1) * rto_base +
			  (boundary - linear_backoff_thresh) * TCP_RTO_MAX;

	return (tcp_time_stamp - start_ts) >= timeout;
}

/* A write timeout has occurred. Process the after effects. */
/*
 * �������ش�֮��,��Ҫ��⵱ǰ����Դʹ��
 * ���.����ش��ﵽ��������Ҫ�����ر��׽���
 */

// tcp write timeout
static int tcp_write_timeout(struct sock *sk)
{
	struct inet_connection_sock *icsk = inet_csk(sk);
	int retry_until;
	bool do_reset, syn_set = 0;

    /*
	 * �ڽ������ӽ׶γ�ʱ,����Ҫ���ʹ�õ�
	 * ·�ɻ�����,����ȡ���Դ��������ֵ.
	 */
	if ((1 << sk->sk_state) & (TCPF_SYN_SENT | TCPF_SYN_RECV)) {
		if (icsk->icsk_retransmits)
			dst_negative_advice(sk);
		retry_until = icsk->icsk_syn_retries ? : sysctl_tcp_syn_retries;
		syn_set = 1;
	} else {
	    /*
		 * ���ش������ﵽsysctl_tcp_retries1ʱ,����Ҫ����
		 * �ڶ����.��ɺڶ���������ʹ�õ�
		 * ·�ɻ�����.
		 * ϵͳ����·��MTU����ʱ,���·��MTU���ֵ�
		 * �������ݿ��еĿ���û�п���,���俪��,
		 * ������PMTUͬ��MSS.����,����ǰ·��MTU����
		 * ������˵��һ����Ϊ���������˵�����
		 * �趨·��MTU��������,������·��MTUͬ��MSS.
		 */
		if (retransmits_timed_out(sk, sysctl_tcp_retries1, 0)) {
			/* Black hole detection */
			tcp_mtu_probing(icsk, sk);

			dst_negative_advice(sk);
		}

        /*
		 * �����ǰ�׽��������ѶϿ��������ر�,��
		 * ��Ҫ�Ե�ǰʹ�õ���Դ���м��.��ǰ�Ĺ�
		 * ���׽��������ﵽsysctl_tcp_max_orphans���ߵ�ǰ
		 * ��ʹ���ڴ�ﵽӲ������ʱ,��Ҫ���̹ر�
		 * ���׽���,����Ȼ������TCP�Ĺ淶,��Ϊ�˷�
		 * ֹDoS����������ô����.
		 */
		retry_until = sysctl_tcp_retries2;
		if (sock_flag(sk, SOCK_DEAD)) {
			const int alive = (icsk->icsk_rto < TCP_RTO_MAX);

			retry_until = tcp_orphan_retries(sk, alive);
			do_reset = alive ||
				   !retransmits_timed_out(sk, retry_until, 0);

			if (tcp_out_of_resources(sk, do_reset))
				return 1;
		}
	}

    /*
	 * ���ش������ﵽ���������ش����ޡ���ʱ
	 * �ش����޻�ȷ�������쳣�ڼ�����������
	 * ��������֮һʱ��������ر��׽��֣���
	 * ����Ҫ������Ӧ�Ĵ���
	 */
	if (retransmits_timed_out(sk, retry_until, syn_set)) {
		/* Has it gone just too far? */
		tcp_write_err(sk);
		return 1;
	}
	return 0;
}

/*
 * ��ʱACK"��ʱ����TCP�յ����뱻ȷ�ϵ��������Ϸ���
 * ȷ�ϵĶ�ʱ�趨��TCP��200ms����ȷ����Ӧ�������
 * ��200ms�ڣ�������Ҫ�ڸ������Ϸ��ͣ���ʱACK��Ӧ��
 * ��������һ���ͻضԶˣ���Ϊ�Ӵ�ȷ�ϡ�
 */
static void tcp_delack_timer(unsigned long data)
{
	struct sock *sk = (struct sock *)data;
	struct tcp_sock *tp = tcp_sk(sk);
	struct inet_connection_sock *icsk = inet_csk(sk);

	bh_lock_sock(sk);
	/*
	 * ���������ƿ��ѱ��û�����������
	 * ���ʱ������������ֻ����������
	 * ��ʱ����ʱʱ�䣬ͬʱ����blocked
	 * ��ǡ�
	 */
	if (sock_owned_by_user(sk)) {
		/* Try again later. */
		icsk->icsk_ack.blocked = 1;
		NET_INC_STATS_BH(sock_net(sk), LINUX_MIB_DELAYEDACKLOCKED);
		sk_reset_timer(sk, &icsk->icsk_delack_timer, jiffies + TCP_DELACK_MIN);
		goto out_unlock;
	}

    /*
	 * ���ջ���
	 */
	sk_mem_reclaim_partial(sk);

    /*
	 * ���TCP״̬ΪCLOSE������û��������ʱ����
	 * ACK��ʱ��������������һ��������
	 */
	if (sk->sk_state == TCP_CLOSE || !(icsk->icsk_ack.pending & ICSK_ACK_TIMER))
		goto out;

    /*
	 * �����ʱʱ�仹δ���������¸�λ��ʱ����
	 * Ȼ���˳���
	 */
	if (time_after(icsk->icsk_ack.timeout, jiffies)) {
		sk_reset_timer(sk, &icsk->icsk_delack_timer, icsk->icsk_ack.timeout);
		goto out;
	}

	/*
	 * �����ɺ���ʽ�����ӳ�ȷ�ϴ���֮ǰ��
	 * ��ȥ��ICSK_ACK_TIMER��־��
	 */
	icsk->icsk_ack.pending &= ~ICSK_ACK_TIMER;

    /*
	 * ���ucopy���ƿ��е�prequeue���в�Ϊ�գ���
	 * ͨ��sk_backlog_rcv�ӿڴ���sk_backlog_rcv�����е�
	 * SKB��TCP��sk_backlog_rcv�ӿ�Ϊtcp_v4_do_rcv()��������������ӵ�sk->sk_receive_queue�����С�
	 */
	if (!skb_queue_empty(&tp->ucopy.prequeue)) {
		struct sk_buff *skb;

		NET_INC_STATS_BH(sock_net(sk), LINUX_MIB_TCPSCHEDULERFAILED);

		while ((skb = __skb_dequeue(&tp->ucopy.prequeue)) != NULL)
			sk_backlog_rcv(sk, skb);

		tp->ucopy.memory = 0;
	}

    /*
	 * �����ʱ��ACK��Ҫ���ͣ������tcp_send_ack()����
	 * ������ACK�Σ��ڷ���ACK��֮ǰ�����뿪pingpong
	 * ģʽ���������趨��ʱȷ�ϵĹ���ֵ��
	 */
	if (inet_csk_ack_scheduled(sk)) {
		if (!icsk->icsk_ack.pingpong) {
			/* Delayed ACK missed: inflate ATO. */
			icsk->icsk_ack.ato = min(icsk->icsk_ack.ato << 1, icsk->icsk_rto);
		} else {
			/* Delayed ACK missed: leave pingpong mode and
			 * deflate ATO.
			 */
			icsk->icsk_ack.pingpong = 0;
			icsk->icsk_ack.ato      = TCP_ATO_MIN;
		}
		tcp_send_ack(sk);
		NET_INC_STATS_BH(sock_net(sk), LINUX_MIB_DELAYEDACKS);
	}
	TCP_CHECK_TIMER(sk);

out:
	if (tcp_memory_pressure)
		sk_mem_reclaim(sk);
out_unlock:
	bh_unlock_sock(sk);
	sock_put(sk);
}

/*
 * "����"��ʱ���ڶԶ�ͨ����մ���Ϊ0����ֹTCP��������
 * ����ʱ�趨���������ӶԶ˷��͵Ĵ���ͨ�治�ɿ�(ֻ��
 * ���ݲŻ�ȷ�ϣ�ACK����ȷ��)������TCP�����������ݵĺ�
 * �����ڸ����п��ܶ�ʧ����ˣ����TCP�����ݷ��ͣ���
 * �Զ�ͨ����մ���Ϊ0���������ʱ����������ʱ����
 * �Զ˷���1�ֽڵ����ݣ����ж϶Զ˽��մ����Ƿ��Ѵ򿪡�
 * ���ش���ʱ�����ƣ�������ʱ���ĳ�ʱֵҲ�Ƕ�̬����ģ�
 * ȡ�������ӵ�����ʱ�䣬��5~60s֮��ȡֵ��
 * tcp_probe_timer()Ϊ������ʱ����ʱ�Ĵ���������̽�ⶨʱ�����ǵ����յ��Զ˵�windowΪ0��ʱ����Ҫ̽��Զ˴����Ƿ���
 */ //������probe���ķ�����tcp_send_probe0�е�tcp_write_wakeup             ̽�ⶨʱ����tcp_ack�����м�� ������__tcp_push_pending_frames�е�tcp_check_probe_timer����
static void tcp_probe_timer(struct sock *sk) ////tcp_write_timer�������ݱ��ش�tcp_retransmit_timer�ʹ���̽�ⶨʱ��tcp_probe_timer
{
	struct inet_connection_sock *icsk = inet_csk(sk);
	struct tcp_sock *tp = tcp_sk(sk);
	int max_probes;

	if (tp->packets_out || !tcp_send_head(sk)) {
		icsk->icsk_probes_out = 0;
		return;
	}

	/* *WARNING* RFC 1122 forbids this
	 *
	 * It doesn't AFAIK, because we kill the retransmit timer -AK
	 *
	 * FIXME: We ought not to do it, Solaris 2.5 actually has fixing
	 * this behaviour in Solaris down as a bug fix. [AC]
	 *
	 * Let me to explain. icsk_probes_out is zeroed by incoming ACKs
	 * even if they advertise zero window. Hence, connection is killed only
	 * if we received no ACKs for normal connection timeout. It is not killed
	 * only because window stays zero for some time, window may be zero
	 * until armageddon and even later. We are in full accordance
	 * with RFCs, only probe timer combines both retransmission timeout
	 * and probe timeout in one bottle.				--ANK
	 */
	max_probes = sysctl_tcp_retries2;

    /*
	 * ���������ѶϿ����׽��ּ����رյ����
	 */
	if (sock_flag(sk, SOCK_DEAD)) {
	    /*
		 * TCPЭ��涨RTT�����ֵΪ120s(TCP_RTO_MAX)�����
		 * ����ͨ����ָ���˱��㷨�ó��ĳ�ʱʱ����
		 * RTT���ֵ��ȣ����ж��Ƿ���Ҫ���Է�����
		 * RST��
		 */
		const int alive = ((icsk->icsk_rto << icsk->icsk_backoff) < TCP_RTO_MAX);

        /*
		 * ��������ѶϿ����׽��ּ����رգ����ȡ��
		 * �رձ���TCP����ǰ���Դ��������ޡ�
		 */
		max_probes = tcp_orphan_retries(sk, alive);

        /*
		 * �ͷ���Դ��������׽������ͷŹ����б��رգ�
		 * �������ٷ��ͳ���̽����ˡ�
		 */
		if (tcp_out_of_resources(sk, alive || icsk->icsk_probes_out <= max_probes))
			return;
	}

	if (icsk->icsk_probes_out > max_probes) {
		tcp_write_err(sk);
		/*
		 * ���������ʱ���򱣻ʱ�������Է��ͳ���δ��ȷ��
		 * ��TCP����Ŀ�ﵽ���ޣ���������������ͬʱ�ر�TCP�׽��֡�
		 */
	} else {
		/* Only send another probe if we didn't close things up. */
		/*
		 * ������һ�η��ͳ�����ʱ����
		 */
		tcp_send_probe0(sk);
	}
}

/*
 *	The TCP retransmit timer.
 */
////tcp_write_timer�������ݱ��ش�tcp_retransmit_timer�ʹ���̽�ⶨʱ��tcp_probe_timer
//��tcp_event_new_data_sent��prior_packetsΪ0ʱ�Ż�������ʱ��,��prior_packets���Ƿ���δȷ�ϵĶεĸ���,Ҳ����˵��������˺ܶ��,���ǰ��Ķ�û��ȷ��,��ô���淢�͵�ʱ�򲻻����������ʱ��.
//tcp_rearm_rto ///Ϊ0˵�����еĴ���Ķζ��Ѿ�acked����ʱremove��ʱ��������������ʱ����  
void tcp_retransmit_timer(struct sock *sk)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct inet_connection_sock *icsk = inet_csk(sk);

    /*
	 * �����ʱ�ӷ��Ͷ�������Ķζ���
	 * �õ���ȷ��,�������ش�����.
	 */
	if (!tp->packets_out)
		goto out;

	WARN_ON(tcp_write_queue_empty(sk));

    /*
	 * ���ش������У������ʱ�ش���ʱ����TCP_RTO_MAX(120s)��û�н���
	 * ���Է���ȷ�ϣ�����Ϊ�д�����������tcp_write_err()�������
	 * �ر��׽��֣�Ȼ�󷵻أ�����TCP����ӵ�����Ƶ�LOSS״̬��������
	 * �����ش������еĵ�һ���Ρ�
	 */
	if (!tp->snd_wnd && !sock_flag(sk, SOCK_DEAD) &&
	    !((1 << sk->sk_state) & (TCPF_SYN_SENT | TCPF_SYN_RECV))) {
		/* Receiver dastardly shrinks window. Our retransmits
		 * become zero probes, but we should not timeout this
		 * connection. If the socket is an orphan, time it out,
		 * we cannot allow such beasts to hang infinitely.
		 */
#ifdef TCP_DEBUG
		struct inet_sock *inet = inet_sk(sk);
		if (sk->sk_family == AF_INET) {
			LIMIT_NETDEBUG(KERN_DEBUG "TCP: Peer %pI4:%u/%u unexpectedly shrunk window %u:%u (repaired)\n",
			       &inet->inet_daddr, ntohs(inet->inet_dport),
			       inet->inet_num, tp->snd_una, tp->snd_nxt);
		}
#if defined(CONFIG_IPV6) || defined(CONFIG_IPV6_MODULE)
		else if (sk->sk_family == AF_INET6) {
			struct ipv6_pinfo *np = inet6_sk(sk);
			LIMIT_NETDEBUG(KERN_DEBUG "TCP: Peer %pI6:%u/%u unexpectedly shrunk window %u:%u (repaired)\n",
			       &np->daddr, ntohs(inet->inet_dport),
			       inet->inet_num, tp->snd_una, tp->snd_nxt);
		}
#endif
#endif
        /*
		 * ���ش������У������ʱ�ش���ʱ����TCP_RTO_MAX(120s)��û�н���
		 * ���Է���ȷ�ϣ�����Ϊ�д�����������tcp_write_err()�������
		 * �ر��׽��֣�Ȼ�󷵻أ�����TCP����ӵ�����Ƶ�LOSS״̬��������
		 * �����ش������еĵ�һ���Ρ�
		 */
		if (tcp_time_stamp - tp->rcv_tstamp > TCP_RTO_MAX) {
			tcp_write_err(sk);
			goto out;
		}
		tcp_enter_loss(sk, 0);
		tcp_retransmit_skb(sk, tcp_write_queue_head(sk));
		/*
		 * ���ڷ������ش���������ƿ��е�·�ɻ���������£�
		 * ��˽�������������ת��out_reset_timer��ǩ��������
		 */
		__sk_dst_reset(sk);
		goto out_reset_timer;
	}

    //�ߵ�����˵���Ǵ������ӽ����׶λ��߶Է��Ļ�������Ϊ0��


    /*
	 * �������ش�֮��,��Ҫ��⵱ǰ����Դʹ��
	 * ������ش��Ĵ���.����ش������ﵽ����,
	 * ����Ҫ�������ǿ�йر��׽���.���ֻ
	 * ��ʹ�õ���Դ�ﵽʹ�õ�����,�򲻽��д�
	 * ���ش�.
	 */
	if (tcp_write_timeout(sk))
		goto out;

    /*
	 * ����ش�����Ϊ0,˵���ս����ش��׶�,��
	 * ���ݲ�ͬ��ӵ��״̬������ص�����ͳ��.   ��һ���ش������ǶԷ���������������Ҫ����ӵ������
	 */
	if (icsk->icsk_retransmits == 0) {
		int mib_idx;

		if (icsk->icsk_ca_state == TCP_CA_Disorder) {
			if (tcp_is_sack(tp))
				mib_idx = LINUX_MIB_TCPSACKFAILURES;
			else
				mib_idx = LINUX_MIB_TCPRENOFAILURES;
		} else if (icsk->icsk_ca_state == TCP_CA_Recovery) {
			if (tcp_is_sack(tp))
				mib_idx = LINUX_MIB_TCPSACKRECOVERYFAIL;
			else
				mib_idx = LINUX_MIB_TCPRENORECOVERYFAIL;
		} else if (icsk->icsk_ca_state == TCP_CA_Loss) {
			mib_idx = LINUX_MIB_TCPLOSSFAILURES;
		} else {
			mib_idx = LINUX_MIB_TCPTIMEOUTS;
		}
		NET_INC_STATS_BH(sock_net(sk), mib_idx);
	}


    /*
	 * �ж��Ƿ��ʹ��F-RTO�㷨���д���,
	 * ������������tcp_enter_frto()����F-RTO
	 * �㷨�Ĵ���,�������tcp_enter_loss()����
	 * �����RTO�������ش��ָ��׶�.
	 */
	if (tcp_use_frto(sk)) {
		tcp_enter_frto(sk);
	} else {
		tcp_enter_loss(sk, 0);
	}

    /*
	 * ��������ش������ϵĵ�һ��SKBʧ��,��λ
	 * �ش���ʱ��,�ȴ��´��ش�.
	 */
	if (tcp_retransmit_skb(sk, tcp_write_queue_head(sk)) > 0) {
		/* Retransmission failed because of local congestion,
		 * do not backoff.
		 */
		if (!icsk->icsk_retransmits)
			icsk->icsk_retransmits = 1;
		inet_csk_reset_xmit_timer(sk, ICSK_TIME_RETRANS,
					  min(icsk->icsk_rto, TCP_RESOURCE_PROBE_INTERVAL),
					  TCP_RTO_MAX);
		goto out;
	}

	/* Increase the timeout each time we retransmit.  Note that
	 * we do not increase the rtt estimate.  rto is initialized
	 * from rtt, but increases here.  Jacobson (SIGCOMM 88) suggests
	 * that doubling rto each time is the least we can get away with.
	 * In KA9Q, Karn uses this for the first few times, and then
	 * goes to quadratic.  netBSD doubles, but only goes up to *64,
	 * and clamps at 1 to 64 sec afterwards.  Note that 120 sec is
	 * defined in the protocol as the maximum possible RTT.  I guess
	 * we'll have to use something other than TCP to talk to the
	 * University of Mars.
	 *
	 * PAWS allows us longer timeouts and large windows, so once
	 * implemented ftp to mars will work nicely. We will have to fix
	 * the 120 second clamps though!
	 */

	/*
	 * ���ͳɹ���,����ָ���˱��㷨ָ��icsk_backoff
	 * ���ۼ��ش�����icsk_retransmits.
	 */
	icsk->icsk_backoff++;
	icsk->icsk_retransmits++;

out_reset_timer:
	/* If stream is thin, use linear timeouts. Since 'icsk_backoff' is
	 * used to reset timer, set to 0. Recalculate 'icsk_rto' as this
	 * might be increased if the stream oscillates between thin and thick,
	 * thus the old value might already be too high compared to the value
	 * set by 'tcp_set_rto' in tcp_input.c which resets the rto without
	 * backoff. Limit to TCP_THIN_LINEAR_RETRIES before initiating
	 * exponential backoff behaviour to avoid continue hammering
	 * linear-timeout retransmissions into a black hole
	 */
	if (sk->sk_state == TCP_ESTABLISHED &&
	    (tp->thin_lto || sysctl_tcp_thin_linear_timeouts) &&
	    tcp_stream_is_thin(tp) &&
	    icsk->icsk_retransmits <= TCP_THIN_LINEAR_RETRIES) {
		icsk->icsk_backoff = 0;
		icsk->icsk_rto = min(__tcp_set_rto(tp), TCP_RTO_MAX);//����rto����������ʱ��������ʹ��karn�㷨��Ҳ�����´γ�ʱʱ������һ��/  
	} else {
		/* Use normal (exponential) backoff */
		icsk->icsk_rto = min(icsk->icsk_rto << 1, TCP_RTO_MAX);
	}

	/*
	 * ����ش���,��Ҫ���ش���ʱʱ��,Ȼ��λ�ش�
	 * ��ʱ��,�ȴ��´��ش�.
	 */
	inet_csk_reset_xmit_timer(sk, ICSK_TIME_RETRANS, icsk->icsk_rto, TCP_RTO_MAX);
	if (retransmits_timed_out(sk, sysctl_tcp_retries1 + 1, 0))
		__sk_dst_reset(sk);

out:;
}

/*
 * �ش���ʱ����TCP��������ʱ�趨�������ʱ��
 * �ѳ�ʱ���Զ�ȷ�ϻ�δ�����TCP���ش����ݡ�
 * �ش���ʱ���ĳ�ʱʱ��ֵ�Ƕ�̬����ģ�ȡ����
 * TCPΪ�����Ӳ���������ʱ���Լ��ö��ѱ��ش�
 * �Ĵ�����
 */ //tcp_write_timer�������ݱ��ش�tcp_retransmit_timer�ʹ���̽�ⶨʱ��tcp_probe_timer
static void tcp_write_timer(unsigned long data)
{
	struct sock *sk = (struct sock *)data;
	struct inet_connection_sock *icsk = inet_csk(sk);
	int event;

	bh_lock_sock(sk);
	/*
	 * ��������ƿ鱻�û�������������ֻ���Ժ����ԣ�
	 * ����������ö�ʱ����ʱʱ�䡣
	 */
	if (sock_owned_by_user(sk)) {
		/* Try again later */
		sk_reset_timer(sk, &icsk->icsk_retransmit_timer, jiffies + (HZ / 20));
		goto out_unlock;
	}
        /*
         * TCP״̬ΪCLOSE��δ���嶨ʱ���¼�����
         * ������������
         */
	if (sk->sk_state == TCP_CLOSE || !icsk->icsk_pending)
		goto out;

    /*
	 * �����δ����ʱ����ʱʱ�䣬������
	 * ���������������ö�ʱ�����´εĳ�
	 * ʱʱ�䡣
	 */
	if (time_after(icsk->icsk_timeout, jiffies)) {
		sk_reset_timer(sk, &icsk->icsk_retransmit_timer, icsk->icsk_timeout);
		goto out;
	}

    /*
	 * �����ش���ʱ���ͳ�����ʱ�������ǹ�����
	 * һ����ʱ��ʵ�ֵģ��������ݶ�ʱ���¼�
	 * �����ּ���������ֶ�ʱ�������eventΪ
	 * ICSK_TIME_RETRANS�������tcp_retransmit_timer()�����ش�
	 * ���������ΪICSK_TIME_PROBE0�������tcp_probe_timer()
	 * ���г�����ʱ���Ĵ���.
	 */
	event = icsk->icsk_pending;
	icsk->icsk_pending = 0;

	switch (event) {
	case ICSK_TIME_RETRANS:
		tcp_retransmit_timer(sk);
		break;
	case ICSK_TIME_PROBE0:
		tcp_probe_timer(sk);
		break;
	}
	TCP_CHECK_TIMER(sk);

out:
	sk_mem_reclaim(sk);
out_unlock:
	bh_unlock_sock(sk);
	sock_put(sk);
}

/*
 *	Timer for listening sockets
 */

/*
 * tcp_synack_timer()ֻ�Ǽ򵥵ص���inet_csk_reqsk_queue_prune()��
 * ����ɨ�������ɢ�б���Ȼ�����趨��������
 * ��ʱ�������ʱ��ΪTCP_SYNQ_INTERVAL��
 */
static void tcp_synack_timer(struct sock *sk)
{
	inet_csk_reqsk_queue_prune(sk, TCP_SYNQ_INTERVAL,
				   TCP_TIMEOUT_INIT, TCP_RTO_MAX);
}

void tcp_syn_ack_timeout(struct sock *sk, struct request_sock *req)
{
	NET_INC_STATS_BH(sock_net(sk), LINUX_MIB_TCPTIMEOUTS);
}
EXPORT_SYMBOL(tcp_syn_ack_timeout);

void tcp_set_keepalive(struct sock *sk, int val)
{
	if ((1 << sk->sk_state) & (TCPF_CLOSE | TCPF_LISTEN))
		return;

	if (val && !sock_flag(sk, SOCK_KEEPOPEN))
		inet_csk_reset_keepalive_timer(sk, keepalive_time_when(tcp_sk(sk)));
	else if (!val)
		inet_csk_delete_keepalive_timer(sk);
}

/*
 * tcp_keepalive_timer()ʵ����TCP�е�������ʱ��:���ӽ�����ʱ����
 * ���ʱ����FIN_WAIT_2��ʱ��������������������ʱ���ֱ�
 * ����LISTEN��ESTABLISHED��FIN_WAIT_2����״̬����˲����������ǣ�
 * ֻ��򵥵�ͨ����ǰ��TCP״̬�����жϵ�ǰִ�е��Ǻ���
 * ��ʱ����
 * 
 * "����"��ʱ����Ӧ�ý���ѡȡ���׽���SO_KEEPALIVEѡ��ʱ��Ч��
 * ������ӵ���������ʱ�䳬��2Сʱ���򱣻ʱ����ʱ����
 * �Զ˷�������̽��Σ�ǿ�ȶԶ���Ӧ��
 * 1)����ܽ��յ�Ԥ�ڵ���Ӧ����TCP��ȷ���Զ���������������
 *    �ڸ������ٴο��г���2Сʱ֮ǰ��TCP�����ٽ��б���̽�⡣
 * 2)����յ�����������Ӧ����TCP����ȷ���Զ�������������
 * 3)������������ɴα�����Զ�δ�յ���Ӧ����TCP�ٶ��Զ�
 *    �����ѱ������������޷���������������(����ϵͳ������
 * ��δ����)�������ӹ���(�����м��·�������͹��ϻ�绰��
 * ����)��
 * 
 * 
 * FIN_WAIT_1��ʱ��:
 * ��ĳ�����Ӵ�FIN_WAIT_1״̬��Ǩ��FIN_WAIT_2״̬���Ҳ����ٽ���
 * �κ�������ʱ������ζ��Ӧ�ý��̵�����close()����shutdown()��
 * û������TCP�İ�رչ��ܣ�FIN_WAIT_2��ʱ����������ʱʱ��Ϊ
 * 10min���ڶ�ʱ����һ�γ�ʱ���������ó�ʱʱ��Ϊ75s���ڶ���
 * ��ʱ��ر����ӡ����������ʱ����Ŀ����Ϊ�˱���Զ�һֱ
 * ����FIN��ĳ�����ӻ���Զ������FIN_WAIT_2״̬��
 * FIN_WAIT_2��ʱ��������ȫ����tcp_keepalive_timer()��ʵ�֣���ʵ�ϣ�ֻ��
 * �ڴ���FIN_WAIT_2״̬��ʱ�䳬��60sʱ���ŻὫ�ô�����ƿ�ŵ�
 * tcp_keepalive_timer()�д�������sk_timer��ʱ������ʱ60s�Ժ�Ĳ��֣���
 * tcp_time_wait()������������tcp_rcv_state_process
 */

 //ͨ��TCP�Ĳ�ͬ״̬����ʵ�����Ӷ�ʱ����FIN_WAIT_2��ʱ���Լ�TCP���ʱ��
 ////??����:�ش���ʱ����̽�ⶨʱ��Ϊʲô����Ķ�ʱ�������ǰ��sk_reset_timer�Ķ�ʱ�����������أ���ǰ��Ķ�ʱ�����ǲ���������?
    //��Ϊ�������ش���ʱ���Ĺ����У���ʾ�Զ˴����ǲ�Ϊ0�ģ�������̽�ⶨʱ����ʱ��Ҳ�����Ƿ���δ��ȷ�ϵ�ack�ȡ����Ǵ��ڲ�ͬ�Ľ׶Σ����������ǲ�����ͬʱ���ڵ�
    //�����tcp_keepalive_timer��ʱ��Ҳ��һ����
static void tcp_keepalive_timer (unsigned long data)
{
	struct sock *sk = (struct sock *) data;
	struct inet_connection_sock *icsk = inet_csk(sk);
	struct tcp_sock *tp = tcp_sk(sk);
	u32 elapsed;

	/* Only process if socket is not in use. */
	bh_lock_sock(sk);
	/*
	 * ���������ƿ鱻�û������������������趨
	 * ��ʱʱ�䣬0.05s���ٴμ��
	 */
	if (sock_owned_by_user(sk)) {
		/* Try again later. */
		inet_csk_reset_keepalive_timer (sk, HZ/20);
		goto out;
	}

    /*
	 * �����ǰTCP״̬ΪLISTEN����˵��ִ�е�������
	 * ������ʱ��������tcp_synack_timer()������
	 */
	if (sk->sk_state == TCP_LISTEN) { //˵�����ڽ���TCP���ӵĹ����еĶ�ʱ����������
		tcp_synack_timer(sk);
		goto out;
	}

    /*
	 * ����FIN_WAIT_2״̬��ʱ��ʱ��TCP״̬����Ϊ
	 * FIN_WAIT_2���׽���״̬ΪDEAD��
	 */ //tcp_rcv_state_process���յ���һ��FIN ack������TCP_FIN_WAIT2״̬
	if (sk->sk_state == TCP_FIN_WAIT2 && sock_flag(sk, SOCK_DEAD)) { //TCP�رչ����еĶ�ʱ���������̣���tcp_rcv_state_process��ת����
	    /*
		 * ͣ����FIN_WAIT_2״̬��ʱ����ڻ����0������£�
		 * ���FIN_WAIT_2��ʱ��ʣ��ʱ�����0�������
		 * tcp_time_wait()����������������Զ˷���RST��
		 * �ر��׽��֡�
		 */
		if (tp->linger2 >= 0) {
			const int tmo = tcp_fin_time(sk) - TCP_TIMEWAIT_LEN;

			if (tmo > 0) {
				tcp_time_wait(sk, TCP_FIN_WAIT2, tmo); //��tcp_rcv_state_process�е�WAIT1״̬���õ���tcp_fin_time-TCP_TIMEWAIT_LEN�����Զ���ĵ�ʱ�����ﴦ��
				goto out;
			}
		}
		tcp_send_active_reset(sk, GFP_ATOMIC);
		goto death;
	}

    //������TCP���ӽ��������еı��������
    /*
	 * ���δ���ñ���ܻ�TCP״̬ΪCLOSE������
	 * �������ء�
	 */
	if (!sock_flag(sk, SOCK_KEEPOPEN) || sk->sk_state == TCP_CLOSE)
		goto out;

    /*
	 * ����������δȷ�ϵĶΣ����߷��Ͷ����л�
	 * ����δ���͵ĶΣ���������������ֻ��������
	 * �����ʱ���ĳ�ʱʱ�䡣
	 */
	elapsed = keepalive_time_when(tp);
	/* It is alive without keepalive 8) */
	if (tp->packets_out || tcp_send_head(sk))
		goto resched;


	elapsed = keepalive_time_elapsed(tp);

	if (elapsed >= keepalive_time_when(tp)) {
	    /*
		 * �����������ʱ�䳬��������ʱ�䣬������δ����
		 * ����̽�����ʱ���ѷ��ͱ���̽�����������ϵͳ
		 * Ĭ�ϵ�������tcp_keepalive_probes�������������ñ���̽��
		 * �εĴ���ʱ���ѷ��ʹ��������˱���̽���������
		 * ��Ҫ�Ͽ����ӣ����Է�����RST�Σ���������Ӧ����
		 * �ر���Ӧ�Ĵ�����ƿ顣
		 */
		if (icsk->icsk_probes_out >= keepalive_probes(tp)) {
			tcp_send_active_reset(sk, GFP_ATOMIC);
			tcp_write_err(sk);
			goto out;
		}

		/* ���ͱ���Σ��������´μ���ʱ����ʱ�䡣*/
		if (tcp_write_wakeup(sk) <= 0) {
			icsk->icsk_probes_out++;
			elapsed = keepalive_intvl_when(tp);
		} else {
			/* If keepalive was lost due to local congestion,
			 * try harder.
			 */
			elapsed = TCP_RESOURCE_PROBE_INTERVAL;
		}
	} else {
		/* It is tp->rcv_tstamp + keepalive_time_when(tp) */
		elapsed = keepalive_time_when(tp) - elapsed;
	}

	TCP_CHECK_TIMER(sk);
	sk_mem_reclaim(sk);

resched:
	inet_csk_reset_keepalive_timer (sk, elapsed);
	goto out;

death:
	tcp_done(sk);

out:
	bh_unlock_sock(sk);
	sock_put(sk);
}

