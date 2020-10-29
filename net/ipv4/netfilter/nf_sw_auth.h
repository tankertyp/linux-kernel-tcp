#ifndef __NF_SW_AUTH_H__
#define __NF_SW_AUTH_H__

#include <linux/list.h>


#define NF_LOCAL_TIME_UTC_SECOND		(8*60*60)//8Сʱ UTCʱ�䣬ͬ����ʱ���8Сʱ

#define NF_SWITCH_HASH_TABLE_SIZE	1024

#define NF_SWITCH_TIME_VALIDE 		1//����ʱ�����Ҫ��
#define NF_SWITCH_TIME_INVALIDE 	0//��ʾʱ�䷶Χ�Ƿ���Ч

#define NF_SWITCH_IN_TO_OUT	1
#define NF_SWITCH_OUT_TO_IN	2
#define NF_SWITCH_BIDIRECTION	3

#define NF_SWITCH_LIMIT_MD_LEN	32

/*Ӧ��Э���������ݽṹ*/
#define NF_APP_ITEM_REL_TYPE_UNDEFINED 0xff
#define NF_APP_ITEM_REL_TYPE_ANY       0
#define NF_APP_ITEM_REL_TYPE_EQUAL     1
#define NF_APP_ITEM_REL_TYPE_LEEQUAL        5
#define NF_APP_ITEM_REL_TYPE_GEEQUAL        6
#define NF_APP_ITEM_REL_TYPE_IN        7
#define NF_APP_ITEM_REL_TYPE_ENUM      9

/*�б�scope_list�������Ľڵ�Ķ˿ڷ�Χ���ݽṹ���£�*/
/*���Э�����TCP��*/
struct nf_ac_tcp_port_scope{
	unsigned char src_op;		/*Դ�˿ڹ�ϵ =  <=  >=  IN  ö�٣�ANY   IN��ʾ����*/
	unsigned char src_num;		/*Դ�˿�����*/
	unsigned char dst_op;		/*Ŀ�Ķ˿ڹ�ϵ*/
	unsigned char dst_num;		/*Ŀ�Ķ˿�����*/
	unsigned short port[0];		/*�˿����飬�������������Դ�˿ں�Ŀ�Ķ˿ڵ�����֮�ͣ�
						  *����˳����Դ�˿�֮����Ŀ�Ķ˿�
						  */
};

/*���Э�����UDP��*/
struct nf_ac_udp_port_scope{
	unsigned char src_op;		/*Դ�˿ڹ�ϵ =  <=  >=  IN  ö�٣�ANY*/
	unsigned char src_num;		/*Դ�˿�����*/
	unsigned char dst_op;		/*Ŀ�Ķ˿ڹ�ϵ*/
	unsigned char dst_num;		/*Ŀ�Ķ˿�����*/
	unsigned short port[0];		/*�˿����飬�������������Դ�˿ں�Ŀ�Ķ˿ڵ�����֮�ͣ�
						  *����˳����Դ�˿�֮����Ŀ�Ķ˿�
						  */
};

/*���Э�����ICMP��*/
struct nf_ac_icmp_scope{
	unsigned char type_op;		/*ICMP���͹�ϵ =  <=  >=  IN  ö�٣�ANY*/
	unsigned char type_num;	/*Դ�˿�����*/
	unsigned char code_op;		/*����ֵ�Ĺ�ϵ*/
	unsigned char code_num;	/*����ֵ������*/
	unsigned char array[0];		/*���ͺʹ������飬����������������ͺʹ��������
						  *����˳������������֮���Ǵ�������
						  */
};

typedef struct _nf_app_coding_content_scope{
	struct list_head lh;
	unsigned char proto;//yang Ӧ��Э���������Э������
	union {
		struct nf_ac_tcp_port_scope tcp;
		struct nf_ac_udp_port_scope udp;
		struct nf_ac_icmp_scope icmp;
	}content;
}nf_app_coding_content_scope;


#define NF_APP_STATUS_ON	1
#define NF_APP_STATUS_OFF	0
typedef struct _nf_app_coding{//����������һ��Ӧ��Э��
	struct hlist_node hlist;//ͨ�����������ӵ�gate_app_coding_kernel_hash_array��
	char sequence[NF_SWITCH_LIMIT_MD_LEN+1];//Ӧ��Э������ index 
	unsigned int h_seq;//yang ����ֵsequenceת��Ϊseq  ������_nf_gate_md5_to_hseq
	unsigned char status;/*���û������� ҳ���Ͽ������úͽ��ø���Ӧ��Э�� */

    /*
    �޿�(�޿�) 15:42:37
                /// </summary>
                TCP = ApprotocolControlLevelEnum.LevelOne,
                /// <summary>
                /// 
                /// </summary>
                UDP = ApprotocolControlLevelEnum.LevelOne,
                /// <summary>
                /// 
                /// </summary>
                ICMP = ApprotocolControlLevelEnum.LevelOne,
                /// <summary>
                /// 
                /// </summary>
                PING = ApprotocolControlLevelEnum.LevelOne,
                /// <summary>
                /// 
                /// </summary>
                HTT
    �޿�(�޿�) 15:42:37
    P = ApprotocolControlLevelEnum.LevelOne,
                /// <summary>
                /// 
                /// </summary>
                SMTP = ApprotocolControlLevelEnum.LevelOne,
                /// <summary>
                /// 
                /// </summary>
                FTP = ApprotocolControlLevelEnum.LevelOne,
                /// <summary>
                /// 
                /// </summary>
                POP3 = ApprotocolControlLevelEnum.LevelOne
    �޿�(�޿�) 15:42:37
     /// <summary>
                /// 
                /// </summary>
                LDG = ApprotocolControlLevelEnum.levelThree,
                /// <summary>
                /// 
                /// </summary>
                SDG = ApprotocolControlLevelEnum.levelThree,
                /// <summary>
                /// 
                /// </summary>
                RTITP = ApprotocolControlLevelEnum.levelThree,
                /// <summary>
                /// 
                /// </summary>
                CSMXP = ApprotocolControlLevelEnum.levelThree,
                /// <summary>
                /// 
    �޿�(�޿�) 15:42:50
    one��two��three�ֱ��Ӧ1,2,3*/
	unsigned char intensity;//��ӦMCP��XML�����"CtrlLevel"
	unsigned char control_type;////�����ģ��̱��ģ�ʵʱ���ĵ� �ο�_gate_show_app_control_type   ʵ����ûʲô��
	unsigned int pro_num;//��Э��ĸ��� ָ������Э����TCP UDP��ICMP�ĸ���  ����2��TCP һ��UDP��4��ICMP�����ֵΪ7
	char* name;//Э����

    //            Э�� 	Դ�˿�/���͹�ϵ 	Դ�˿�/ֵ 	Ŀ�Ķ˿�/���͹�ϵ 	Ŀ�Ķ˿�/ֵ 
	//��������   TCP	  =	                 5555 	       any	
	struct list_head app_coding_list;//�����Э��������ο�WEBҳ��  nf_app_coding_content_scope  �������Ӧ��Э���TCP  UDP  ICMP
}nf_app_coding;


/*===============================================================*/

#define NF_ADDR_ITEM_REL_TYPE_ANY       0
#define NF_ADDR_ITEM_REL_TYPE_EQUAL        1
#define NF_ADDR_ITEM_REL_TYPE_IN      2
#define NF_ADDR_ITEM_REL_TYPE_ENUM      3

typedef struct _nf_sw_limit_address_item{
	struct list_head lh;
	unsigned char type;//����  ����  ö�� �ο�WEB
	unsigned char count;//��������䣬�����������������⣬��arry[0]��arry[1]������������޵�ַ�������arry[2],arry[3]�����������ַ
	unsigned int array[0];
}nf_sw_limit_addr_item;

//��:�����ַ�������������1.2.3.3/17,12.3.3.3/17 ����ʵ����web�ǰ��շ������η������ģ�Ҳ����_nf_sw_limit_address_itemΪ2
//�����ַ�������������ö�� 1.1.1.1,2.2.2.2,3.3.3.3������һ�η��͹����ģ�item����Ϊ1
//�����ַ��������������1.2.3.3-1.3.3.3�����ַ��1.2.3.3,1.3.3.2,1.2.5.2 ����itemΪ1,arry��������1.2.3.3 1.3.3.3 1.2.3.3 1.3.3.2 1.2.5.2 
//���δ���⣬��countΪ0
typedef struct _nf_sw_limit_addr{
	struct hlist_node hlist;
	char sequence[NF_SWITCH_LIMIT_MD_LEN+1];//YANG  ��ַ��������index
	unsigned int h_seq;//ͨ��_nf_gate_md5_to_hseq������ĵ�ַ����indexת��Ϊseq
	char* name;//��ַ������
	struct list_head item_list;//_nf_sw_limit_address_item
}nf_sw_limit_addr;


#define NF_ITEM_REL_TYPE_ANY       0
#define NF_ITEM_REL_TYPE_IN        1//��ʾ��ĳ��ʱ�䵽ĳ��ʱ�䣬ʱ����������  1����㵽12������
#define NF_ITEM_REL_TYPE_ENUM      2//��ĳһ�쵽ĳһ���еļ��㵽����ʱ����ǲ�������  1�յ�12���е���㵽����֮��

//����Ϊany��ʱ��day,start_tm,end_tm��Ч����Ϊ�����ʱ��day��Ч
typedef struct _nf_sw_limit_time_item{
	struct list_head lh;
	unsigned char tm_type;//ʱ���������     ����   ����   ö��  ����Ϊany��ʱ��day,start_tm,end_tm��Ч����Ϊ�����ʱ��day��Ч
	unsigned char day;//���� ����λ��Ĺ�ϵ���ӵ�λ����Σһ���� ������ ����һ ����������    _nf_show_sw_limit_time_day
	unsigned int start_tm;//��ʼʱ��  ʱ���           ���Ϊ����Ļ��������ֵת�����ʵ��Ϊstart_tm:2013-12-1(������ʼʱ��) 14:55:0(ʱ����ʼʱ��) ������������ʵʱ�䣬ʱ�����ʵʱ�� end_tm:2013-12-20 21:57:1����
	unsigned int end_tm;
}nf_sw_limit_time_item;

typedef struct _nf_sw_limit_time{
	struct hlist_node hlist;//�ӵ�gate_sw_limit_time_kernel_hash_array  hash����
	char sequence[NF_SWITCH_LIMIT_MD_LEN+1];//����index
	unsigned int h_seq;//����ת�����seqֵ
	unsigned int effective_area;		/*������*/
	char* name;//ʱ���������
	struct list_head item_list;//_nf_sw_limit_time_item
	struct timer_list timer;
	unsigned int tm_flag;
}nf_sw_limit_time;

/*===============================================================*/
#define NF_SW_AUTH_SRC_TYPE_ANY		0
#define NF_SW_AUTH_SRC_TYPE_OBJ		1
#define NF_SW_AUTH_SRC_TYPE_PREFIX	2

#define NF_SW_AUTH_DST_TYPE_ANY		0
#define NF_SW_AUTH_DST_TYPE_OBJ		1
#define NF_SW_AUTH_DST_TYPE_PREFIX	2

#define NF_SW_AUTH_TIME_TYPE_ANY		0//ʱ�����  ����
#define NF_SW_AUTH_TIME_TYPE_OBJ		1//ʱ���������Ϊ�������ö�٣��ο�WEB��ҳ

typedef struct _nf_switch_id_prefix{
	unsigned int id;
	unsigned int id_prefix;
}nf_switch_id_prefix;

typedef struct _nf_switch_app_coding{
	struct list_head lh;
	char app_seq[NF_SWITCH_LIMIT_MD_LEN+1];//ͨ����ֵ��ȡgate_app_coding_kernel_hash_array��ֵ
}nf_switch_app_coding;

#define NF_SW_AUTH_AREA_ALL		0
#define NF_SW_AUTH_AREA_REGION	1
#define NF_SW_AUTH_AREA_AGENT	2


//һ����������ֻ�����һ��ʱ����� һ����ַ���� ���Զ��Ӧ��Э��
typedef struct _nf_switch_authority{
	struct hlist_node hlist;
	char sequence[NF_SWITCH_LIMIT_MD_LEN+1];//�ù��������ֵ
	unsigned int h_seq;
	unsigned char log_level;			/*��־����  yang ʵ����ûʲô�� */
	char* des;
	struct list_head app_coding_list;	/*Ӧ��Э�����  Ӧ��Э��ֱ�Ӽӵ��������� nf_switch_app_coding */
	unsigned char dst_type;//��ӽ��������ʱ��Ŀ�ĵ�ַ����:���� ��ַ����  ��ַ/��ַǰ׺
	union{
		unsigned int obj;
		nf_switch_id_prefix prefix;
	}dst;
	char dst_seq[NF_SWITCH_LIMIT_MD_LEN+1];//ͨ����ֵ��Ϊ���У��Ӷ���ȡgate_sw_limit_addr_kernel_hash_array��ֵ
	unsigned char time_type;
	char tm_obj[NF_SWITCH_LIMIT_MD_LEN+1];//ʱ��������� index      ʱ��������Ч��ͨ����ʱ�������
	unsigned int tm_flag;//ʱ������Ƿ���Ч��ֻ����Ч�ù��������         ʱ�����Ϊ�������͵�ʱ����1   ����������__gate_sw_time_validate_authority
}nf_switch_authority;


/*********************************************
	
*/
typedef struct _nf_switch_user_rule_index{//Ϊ�û�����Ĺ���  �ýڵ���ӵ�_nf_switch_user_idip��rule_list
	struct list_head lh;//
	char rule_seq[NF_SWITCH_LIMIT_MD_LEN+1];
}nf_switch_user_rule_index;

typedef struct _nf_switch_user_idip{
	struct hlist_node id_hlist;
	struct hlist_node ip_hlist;
	unsigned int id;
	unsigned int ip;
	struct list_head rule_list;//nf_switch_user_rule_index
	struct list_head dynamic_rule_list;
}nf_switch_user_idip;

typedef struct _nf_switch_auth_mem_count{
	int app_coding_scp;//Ӧ��Э���������Э���ܸ���
	int app_coding;//Ӧ��Э���������web�������һ����ʱ������ͻ��һ��ɾ��һ����ʱ��ͻ��1
	int app_coding_name;
	int limit_time_item;
	int limit_time;
	int limit_time_name;
	int limit_addr_item;
	int limit_addr;
	int limit_addr_name;//��ַ�������
	int pri_des;//
	int pri;//�����������,�����û��Զ�������ϵͳ����
	int pri_app;//Ӧ��Э�鱻���õĴ���������ϵͳ������û��Զ������Ӧ�õ�
} nf_switch_auth_mem_count;

extern spinlock_t gate_privilege_lock;

static inline void lock_privilege(void)
{
	spin_lock_bh(&gate_privilege_lock);
}

static inline void unlock_privilege(void)
{
	spin_unlock_bh(&gate_privilege_lock);
}

#endif
