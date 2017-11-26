
#define ENABLE		(1)
#define DISABLE		(0)

#define DHCP_EN		DISABLE	/* ∆Ù”√DHCPπ¶ƒ‹ */

#if (DHCP_EN == DISABLE)
	#define LOCAL_IP	"192.168.120.86"
	#define GATEWAY_IP	"192.168.120.1"
#endif

/* TCP */



