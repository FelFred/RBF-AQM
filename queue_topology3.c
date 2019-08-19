                                                                                                                                                                                                                                                                                                                                                                                           ";
#include <string.h>



/* OPNET system definitions */
#include <opnet.h>



/* Header Block */

#include <ip_dgram_sup.h>
#include <tcp_seg_sup.h>

// routing table size
#define RT_SIZE 8

#define PKTIN op_intrpt_type()==OPC_INTRPT_STRM
#define PKTOUT op_intrpt_type()==OPC_INTRPT_SELF
#define FINISH op_intrpt_type()==OPC_INTRPT_ENDSIM
#define WKSTN (dest_addr % 2)==1
#define SERVER (dest_addr % 2)==0


/* End of Header Block */

#if !defined (VOSD_NO_FIN)
#undef	BIN
#undef	BOUT
#define	BIN		FIN_LOCAL_FIELD(_op_last_line_passed) = __LINE__ - _op_block_origin;
#define	BOUT	BIN
#define	BINIT	FIN_LOCAL_FIELD(_op_last_line_passed) = 0; _op_block_origin = __LINE__;
#else
#define	BINIT
#endif /* #if !defined (VOSD_NO_FIN) */



/* State variable definitions */
typedef struct
	{
	/* Internal state tracking for FSM */
	FSM_SYS_STATE
	/* State Variables */
	FILE *	                 		fp                                              ;
	FILE *	                 		fp_loss                                         ;
	FILE *	                 		fp64                                            ;
	FILE *	                 		fp_aggr                                         ;
	FILE *	                 		debt_debug_file                                 ;
	FILE *	                 		link_output_file                                ;
	FILE *	                 		loss_file                                       ;
	FILE *	                 		destroyed_file                                  ;
	FILE *	                 		destroyed0_file                                 ;
	FILE *	                 		total_file                                      ;
	FILE *	                 		params_file                                     ;
	FILE *	                 		qstats_file                                     ;
	FILE *	                 		loss_pdf_file                                   ;
	FILE *	                 		remaining_debt_file                             ;
	FILE *	                 		qdata_file                                      ;
	FILE *	                 		main_loss_file                                  ;
	int	                    		port                                            ;
	Packet *	               		pkt                                             ;
	Objid	                  		subq_objid                                      ;
	Objid	                  		queue_objid                                     ;
	Objid	                  		subq_comp_attr_objid                            ;
	int	                    		subq_size                                       ;
	Objid	                  		node_id                                         ;
	double	                 		time_stamp                                      ;
	Packet *	               		tcp_pkt                                         ;
	int	                    		subq_index                                      ;
	int	                    		test_int                                        ;
	int	                    		test_index                                      ;
	IpT_Dgram_Fields *	     		fields_ip                                       ;
	int	                    		ip_address                                      ;
	int	                    		dest_address                                    ;
	double	                 		reserved_time                                   ;
	double	                 		service_time                                    ;
	int	                    		rtt1                                            ;
	int	                    		rtt2                                            ;
	double	                 		last_rtt                                        ;
	double	                 		delay_S1                                        ;
	double	                 		delay_S2                                        ;
	double	                 		delay_W1                                        ;
	double	                 		delay_W2                                        ;
	int	                    		pkt_loss1                                       ;
	int	                    		pkt_loss2                                       ;
	int	                    		pkt_total1                                      ;
	int	                    		pkt_total2                                      ;
	TcpT_Seg_Fields *	      		fields_tcp                                      ;
	int	                    		prev_seq1                                       ;
	int	                    		prev_seq2                                       ;
	char *	                 		packet_format[8]                                ;
	double	                 		intrinsic_loss                                  ;
	char	                   		ip_id[32]                                       ;
	int *	                  		num_formatted_fields                            ;
	char	                   		fmt_name[16]                                    ;
	double	                 		threshold                                       ;
	double	                 		red_loss                                        ;
	double	                 		var_loss                                        ;
	double	                 		aggr_coef                                       ;	/* aggressivity coefficient */
	int	                    		intr_loss_c1                                    ;
	int	                    		intr_loss_c2                                    ;
	int	                    		q_loss_c1                                       ;
	int	                    		q_loss_c2                                       ;
	int	                    		fq_loss_c1                                      ;
	int	                    		fq_loss_c2                                      ;
	int	                    		debt_loss_c1                                    ;
	int	                    		debt_loss_c2                                    ;
	Objid	                  		queue_id                                        ;
	Objid	                  		app_id                                          ;
	Objid	                  		app_defs_objid                                  ;
	Objid	                  		dest_pref_objid                                 ;
	int	                    		dest_pref_value                                 ;
	int	                    		cnt_total_in                                    ;
	int	                    		cnt_total_out                                   ;
	int	                    		cnt_total_destroyed                             ;
	int	                    		dest_addr                                       ;
	double	                 		fact_conv                                       ;
	Packet *	               		extract_pkt                                     ;
	Boolean	                		flag_ttf                                        ;
	int	                    		drop_debt                                       ;
	int	                    		drop_debt0                                      ;
	int	                    		drop_debt1                                      ;
	int	                    		drop_debt2                                      ;
	int	                    		drop_debt3                                      ;
	int	                    		cur_seq                                         ;
	int	                    		last_ok                                         ;
	int	                    		last_ok0                                        ;
	int	                    		last_ok1                                        ;
	int	                    		last_ok2                                        ;
	int	                    		last_ok3                                        ;
	int	                    		drop_reg3[500]                                  ;
	int	                    		drop_reg2[500]                                  ;
	int	                    		drop_reg1[500]                                  ;
	int	                    		drop_reg0[500]                                  ;
	int	                    		drop_reg[500]                                   ;
	int	                    		L                                               ;
	int	                    		i                                               ;
	Boolean	                		droppable                                       ;
	int	                    		nxt_idx                                         ;
	int	                    		nxt_idx0                                        ;
	int	                    		nxt_idx1                                        ;
	int	                    		nxt_idx2                                        ;
	int	                    		nxt_idx3                                        ;
	Boolean	                		repetition                                      ;
	int	                    		outcome                                         ;
	Boolean	                		increase_debt                                   ;
	int	                    		contador_test                                   ;
	Boolean	                		might_drop                                      ;
	int	                    		last_lost                                       ;
	int	                    		last_lost0                                      ;
	int	                    		last_lost1                                      ;
	int	                    		last_lost2                                      ;
	int	                    		last_lost3                                      ;
	int	                    		l11_id                                          ;
	int	                    		l12_id                                          ;
	int	                    		l21_id                                          ;
	int	                    		l22_id                                          ;
	double	                 		d11                                             ;
	double	                 		d12                                             ;
	double	                 		d21                                             ;
	double	                 		d22                                             ;
	double	                 		rtt_c1                                          ;
	double	                 		rtt_c2                                          ;
	int	                    		alg_num                                         ;
	int	                    		pkts_inq                                        ;
	double	                 		q_delay                                         ;
	double	                 		cur_qsize                                       ;
	int	                    		qsize_sample                                    ;
	Boolean	                		smoothing                                       ;
	double	                 		w_q                                             ;
	double	                 		s_red                                           ;
	double	                 		idle_stamp                                      ;
	double	                 		idle_power                                      ;
	double	                 		last_q_record                                   ;
	double	                 		dt_q                                            ;
	int	                    		my_id                                           ;
	char *	                 		bg_dist[25]                                     ;
	double	                 		bg_iat                                          ;
	Boolean	                		recommended_red                                 ;
	Boolean	                		gentle_flag                                     ;
	double	                 		min_th                                          ;
	double	                 		max_p                                           ;
	char *	                 		fbase_str[80]                                   ;
	char *	                 		files_str[80]                                   ;
	double	                 		alpha_feng                                      ;
	double	                 		beta_feng                                       ;
	Boolean	                		feng                                            ;
	int	                    		feng_status                                     ;
	double	                 		max_th                                          ;
	double	                 		target_delay                                    ;
	Boolean	                		sally                                           ;
	double	                 		alpha_ared                                      ;
	double	                 		beta_ared                                       ;
	double	                 		ared_prevtime                                   ;
	double	                 		interval                                        ;
	double	                 		link_cap                                        ;
	double	                 		lambda                                          ;
	int	                    		var_cnt_c1                                      ;
	int	                    		var_cnt_c2                                      ;
	int	                    		dvar_c1                                         ;
	int	                    		dvar_c2                                         ;
	int	                    		d_debt_c1                                       ;
	int	                    		nd_debt_c1                                      ;
	int	                    		d_debt_c2                                       ;
	int	                    		nd_debt_c2                                      ;
	int	                    		c1_stop_loss                                    ;
	int	                    		c2_stop_loss                                    ;
	int	                    		lpdf_c1_cnt                                     ;
	int	                    		lpdf_c2_cnt                                     ;
	int	                    		lpdf_limit                                      ;
	int	                    		outcome4_instance                               ;
	int	                    		red_count                                       ;
	int	                    		routing_table[RT_SIZE]                          ;
	Objid	                  		bottleneck_id                                   ;
	int	                    		rtt_data                                        ;
	} scheduler_TCP_rt_ttf_state;

#define fp                      		op_sv_ptr->fp
#define fp_loss                 		op_sv_ptr->fp_loss
#define fp64                    		op_sv_ptr->fp64
#define fp_aggr                 		op_sv_ptr->fp_aggr
#define debt_debug_file         		op_sv_ptr->debt_debug_file
#define link_output_file        		op_sv_ptr->link_output_file
#define loss_file               		op_sv_ptr->loss_file
#define destroyed_file          		op_sv_ptr->destroyed_file
#define destroyed0_file         		op_sv_ptr->destroyed0_file
#define total_file              		op_sv_ptr->total_file
#define params_file             		op_sv_ptr->params_file
#define qstats_file             		op_sv_ptr->qstats_file
#define loss_pdf_file           		op_sv_ptr->loss_pdf_file
#define remaining_debt_file     		op_sv_ptr->remaining_debt_file
#define qdata_file              		op_sv_ptr->qdata_file
#define main_loss_file          		op_sv_ptr->main_loss_file
#define port                    		op_sv_ptr->port
#define pkt                     		op_sv_ptr->pkt
#define subq_objid              		op_sv_ptr->subq_objid
#define queue_objid             		op_sv_ptr->queue_objid
#define subq_comp_attr_objid    		op_sv_ptr->subq_comp_attr_objid
#define subq_size               		op_sv_ptr->subq_size
#define node_id                 		op_sv_ptr->node_id
#define time_stamp              		op_sv_ptr->time_stamp
#define tcp_pkt                 		op_sv_ptr->tcp_pkt
#define subq_index              		op_sv_ptr->subq_index
#define test_int                		op_sv_ptr->test_int
#define test_index              		op_sv_ptr->test_index
#define fields_ip               		op_sv_ptr->fields_ip
#define ip_address              		op_sv_ptr->ip_address
#define dest_address            		op_sv_ptr->dest_address
#define reserved_time           		op_sv_ptr->reserved_time
#define service_time            		op_sv_ptr->service_time
#define rtt1                    		op_sv_ptr->rtt1
#define rtt2                    		op_sv_ptr->rtt2
#define last_rtt                		op_sv_ptr->last_rtt
#define delay_S1                		op_sv_ptr->delay_S1
#define delay_S2                		op_sv_ptr->delay_S2
#define delay_W1                		op_sv_ptr->delay_W1
#define delay_W2                		op_sv_ptr->delay_W2
#define pkt_loss1               		op_sv_ptr->pkt_loss1
#define pkt_loss2               		op_sv_ptr->pkt_loss2
#define pkt_total1              		op_sv_ptr->pkt_total1
#define pkt_total2              		op_sv_ptr->pkt_total2
#define fields_tcp              		op_sv_ptr->fields_tcp
#define prev_seq1               		op_sv_ptr->prev_seq1
#define prev_seq2               		op_sv_ptr->prev_seq2
#define packet_format           		op_sv_ptr->packet_format
#define intrinsic_loss          		op_sv_ptr->intrinsic_loss
#define ip_id                   		op_sv_ptr->ip_id
#define num_formatted_fields    		op_sv_ptr->num_formatted_fields
#define fmt_name                		op_sv_ptr->fmt_name
#define threshold               		op_sv_ptr->threshold
#define red_loss                		op_sv_ptr->red_loss
#define var_loss                		op_sv_ptr->var_loss
#define aggr_coef               		op_sv_ptr->aggr_coef
#define intr_loss_c1            		op_sv_ptr->intr_loss_c1
#define intr_loss_c2            		op_sv_ptr->intr_loss_c2
#define q_loss_c1               		op_sv_ptr->q_loss_c1
#define q_loss_c2               		op_sv_ptr->q_loss_c2
#define fq_loss_c1              		op_sv_ptr->fq_loss_c1
#define fq_loss_c2              		op_sv_ptr->fq_loss_c2
#define debt_loss_c1            		op_sv_ptr->debt_loss_c1
#define debt_loss_c2            		op_sv_ptr->debt_loss_c2
#define queue_id                		op_sv_ptr->queue_id
#define app_id                  		op_sv_ptr->app_id
#define app_defs_objid          		op_sv_ptr->app_defs_objid
#define dest_pref_objid         		op_sv_ptr->dest_pref_objid
#define dest_pref_value         		op_sv_ptr->dest_pref_value
#define cnt_total_in            		op_sv_ptr->cnt_total_in
#define cnt_total_out           		op_sv_ptr->cnt_total_out
#define cnt_total_destroyed     		op_sv_ptr->cnt_total_destroyed
#define dest_addr               		op_sv_ptr->dest_addr
#define fact_conv               		op_sv_ptr->fact_conv
#define extract_pkt             		op_sv_ptr->extract_pkt
#define flag_ttf                		op_sv_ptr->flag_ttf
#define drop_debt               		op_sv_ptr->drop_debt
#define drop_debt0              		op_sv_ptr->drop_debt0
#define drop_debt1              		op_sv_ptr->drop_debt1
#define drop_debt2              		op_sv_ptr->drop_debt2
#define drop_debt3              		op_sv_ptr->drop_debt3
#define cur_seq                 		op_sv_ptr->cur_seq
#define last_ok                 		op_sv_ptr->last_ok
#define last_ok0                		op_sv_ptr->last_ok0
#define last_ok1                		op_sv_ptr->last_ok1
#define last_ok2                		op_sv_ptr->last_ok2
#define last_ok3                		op_sv_ptr->last_ok3
#define drop_reg3               		op_sv_ptr->drop_reg3
#define drop_reg2               		op_sv_ptr->drop_reg2
#define drop_reg1               		op_sv_ptr->drop_reg1
#define drop_reg0               		op_sv_ptr->drop_reg0
#define drop_reg                		op_sv_ptr->drop_reg
#define L                       		op_sv_ptr->L
#define i                       		op_sv_ptr->i
#define droppable               		op_sv_ptr->droppable
#define nxt_idx                 		op_sv_ptr->nxt_idx
#define nxt_idx0                		op_sv_ptr->nxt_idx0
#define nxt_idx1                		op_sv_ptr->nxt_idx1
#define nxt_idx2                		op_sv_ptr->nxt_idx2
#define nxt_idx3                		op_sv_ptr->nxt_idx3
#define repetition              		op_sv_ptr->repetition
#define outcome                 		op_sv_ptr->outcome
#define increase_debt           		op_sv_ptr->increase_debt
#define contador_test           		op_sv_ptr->contador_test
#define might_drop              		op_sv_ptr->might_drop
#define last_lost               		op_sv_ptr->last_lost
#define last_lost0              		op_sv_ptr->last_lost0
#define last_lost1              		op_sv_ptr->last_lost1
#define last_lost2              		op_sv_ptr->last_lost2
#define last_lost3              		op_sv_ptr->last_lost3
#define l11_id                  		op_sv_ptr->l11_id
#define l12_id                  		op_sv_ptr->l12_id
#define l21_id                  		op_sv_ptr->l21_id
#define l22_id                  		op_sv_ptr->l22_id
#define d11                     		op_sv_ptr->d11
#define d12                     		op_sv_ptr->d12
#define d21                     		op_sv_ptr->d21
#define d22                     		op_sv_ptr->d22
#define rtt_c1                  		op_sv_ptr->rtt_c1
#define rtt_c2                  		op_sv_ptr->rtt_c2
#define alg_num                 		op_sv_ptr->alg_num
#define pkts_inq                		op_sv_ptr->pkts_inq
#define q_delay                 		op_sv_ptr->q_delay
#define cur_qsize               		op_sv_ptr->cur_qsize
#define qsize_sample            		op_sv_ptr->qsize_sample
#define smoothing               		op_sv_ptr->smoothing
#define w_q                     		op_sv_ptr->w_q
#define s_red                   		op_sv_ptr->s_red
#define idle_stamp              		op_sv_ptr->idle_stamp
#define idle_power              		op_sv_ptr->idle_power
#define last_q_record           		op_sv_ptr->last_q_record
#define dt_q                    		op_sv_ptr->dt_q
#define my_id                   		op_sv_ptr->my_id
#define bg_dist                 		op_sv_ptr->bg_dist
#define bg_iat                  		op_sv_ptr->bg_iat
#define recommended_red         		op_sv_ptr->recommended_red
#define gentle_flag             		op_sv_ptr->gentle_flag
#define min_th                  		op_sv_ptr->min_th
#define max_p                   		op_sv_ptr->max_p
#define fbase_str               		op_sv_ptr->fbase_str
#define files_str               		op_sv_ptr->files_str
#define alpha_feng              		op_sv_ptr->alpha_feng
#define beta_feng               		op_sv_ptr->beta_feng
#define feng                    		op_sv_ptr->feng
#define feng_status             		op_sv_ptr->feng_status
#define max_th                  		op_sv_ptr->max_th
#define target_delay            		op_sv_ptr->target_delay
#define sally                   		op_sv_ptr->sally
#define alpha_ared              		op_sv_ptr->alpha_ared
#define beta_ared               		op_sv_ptr->beta_ared
#define ared_prevtime           		op_sv_ptr->ared_prevtime
#define interval                		op_sv_ptr->interval
#define link_cap                		op_sv_ptr->link_cap
#define lambda                  		op_sv_ptr->lambda
#define var_cnt_c1              		op_sv_ptr->var_cnt_c1
#define var_cnt_c2              		op_sv_ptr->var_cnt_c2
#define dvar_c1                 		op_sv_ptr->dvar_c1
#define dvar_c2                 		op_sv_ptr->dvar_c2
#define d_debt_c1               		op_sv_ptr->d_debt_c1
#define nd_debt_c1              		op_sv_ptr->nd_debt_c1
#define d_debt_c2               		op_sv_ptr->d_debt_c2
#define nd_debt_c2              		op_sv_ptr->nd_debt_c2
#define c1_stop_loss            		op_sv_ptr->c1_stop_loss
#define c2_stop_loss            		op_sv_ptr->c2_stop_loss
#define lpdf_c1_cnt             		op_sv_ptr->lpdf_c1_cnt
#define lpdf_c2_cnt             		op_sv_ptr->lpdf_c2_cnt
#define lpdf_limit              		op_sv_ptr->lpdf_limit
#define outcome4_instance       		op_sv_ptr->outcome4_instance
#define red_count               		op_sv_ptr->red_count
#define routing_table           		op_sv_ptr->routing_table
#define bottleneck_id           		op_sv_ptr->bottleneck_id
#define rtt_data                		op_sv_ptr->rtt_data

/* These macro definitions will define a local variable called	*/
/* "op_sv_ptr" in each function containing a FIN statement.	*/
/* This variable points to the state variable data structure,	*/
/* and can be used from a C debugger to display their values.	*/
#undef FIN_PREAMBLE_DEC
#undef FIN_PREAMBLE_CODE
#define FIN_PREAMBLE_DEC	scheduler_TCP_rt_ttf_state *op_sv_ptr;
#define FIN_PREAMBLE_CODE	\
		op_sv_ptr = ((scheduler_TCP_rt_ttf_state *)(OP_SIM_CONTEXT_PTR->_op_mod_state_ptr));


/* Function Block */

#if !defined (VOSD_NO_FIN)
enum { _op_block_origin = __LINE__ + 2};
#endif

static double get_ttf_loss(double r_loss){
	double ttf_loss;

	FIN (get_ttf_loss (r_loss));
	ttf_loss = r_loss * 2;	
	FRET (ttf_loss);
}

static double get_ttf_red_loss(){
	double ttf_red_loss;

	FIN (get_ttf_red_loss ());	
	
	ttf_red_loss = (double) (cur_qsize/((double) subq_size) - threshold)/(1 - threshold);
	ttf_red_loss = (ttf_red_loss < 0)?0:ttf_red_loss;
	
	FRET (ttf_red_loss);
}

static double get_rec_red_loss(){
	double rec_red_loss;
	double th_diff;
	double m1;
	double n1;
	double m2;
	double n2;

	FIN (get_rec_red_loss ());
	
	th_diff = (max_th-min_th);
	m1 = max_p/th_diff;
	n1 = max_p * (-min_th/th_diff);
	
	m2 = (1-max_p)/max_th;
	n2 = 2*max_p -1;
	
	if ((gentle_flag) && (cur_qsize >= max_th)){
		rec_red_loss = m2*cur_qsize + n2;
		red_count = 0;
	} else if ((!gentle_flag) && cur_qsize >= max_th) {
		rec_red_loss = 1;	
		red_count = 0;
	} else {
		rec_red_loss = m1*cur_qsize + n1;
		// red_count check
		if (cur_qsize >= min_th){
			red_count = red_count + 1;
			//red_count = 0;
			rec_red_loss = rec_red_loss/(1-red_count*rec_red_loss);
		} else {
			red_count = -1;
		}
	}	

	
	rec_red_loss = (rec_red_loss < 0)?0:rec_red_loss;
	
	rec_red_loss = (rec_red_loss > 1)?1:rec_red_loss;
	
	FRET (rec_red_loss);
}

static double get_ttf_var_loss(){
	double ttf_var_loss;
	double correction_factor;

	FIN (get_ttf_var_loss ());
	
	if (cur_qsize <= 3*min_th){ // antes 2*min_th
		correction_factor = pow(15,(aggr_coef-last_rtt));
		correction_factor = 1;
	} else {
		correction_factor = 1;
	}
	ttf_var_loss = (double) (correction_factor*aggr_coef/last_rtt)*(correction_factor*aggr_coef/last_rtt)*red_loss/lambda;				
	
	ttf_var_loss = (ttf_var_loss > 1)?1:ttf_var_loss;
	FRET (ttf_var_loss);
}
//0.07

static void get_file_str(const char* extra_str){
		
	FIN (get_file_str (extra_str));
	strcpy(files_str, fbase_str);
	strcat(files_str, extra_str);
	FOUT;
}

static void
read_routing_table ()
	{
	FILE *file;
	// int table[RT_SIZE];
	int	dump;
	int j;
	
	FIN (read_routing_table ())
		
		file = fopen("C:\\Users\\Felipe Fredes\\op_models\\routing_table.txt", "r");	
		// ruta CE: S:\\Google Drive\\op_models\\routing_table.txt
		// ruta FF: C:\\Users\\Felipe Fredes\\op_models\\routing_table.txt
		
		while(fscanf(file, "%d", &dump)==1){
		
			if (dump == my_id){
				
				printf("Routing Table for Queue %d\n", my_id);
				for(j = 0; j < RT_SIZE; j++){
					fscanf(file, "%d", &routing_table[j]);
					// printf("port %d: %d\n", j, table[j]);
				}
				break;
			}
		}
		
	fclose(file);
	// FRET (table);
	FOUT;
}

/* End of Function Block */

/* Undefine optional tracing in FIN/FOUT/FRET */
/* The FSM has its own tracing code and the other */
/* functions should not have any tracing.		  */
#undef FIN_TRACING
#define FIN_TRACING

#undef FOUTRET_TRACING
#define FOUTRET_TRACING

#if defined (__cplusplus)
extern "C" {
#endif
	void scheduler_TCP_rt_ttf (OP_SIM_CONTEXT_ARG_OPT);
	VosT_Obtype _op_scheduler_TCP_rt_ttf_init (int * init_block_ptr);
	void _op_scheduler_TCP_rt_ttf_diag (OP_SIM_CONTEXT_ARG_OPT);
	void _op_scheduler_TCP_rt_ttf_terminate (OP_SIM_CONTEXT_ARG_OPT);
	VosT_Address _op_scheduler_TCP_rt_ttf_alloc (VosT_Obtype, int);
	void _op_scheduler_TCP_rt_ttf_svar (void *, const char *, void **);


#if defined (__cplusplus)
} /* end of 'extern "C"' */
#endif




/* Process model interrupt handling procedure */


void
scheduler_TCP_rt_ttf (OP_SIM_CONTEXT_ARG_OPT)
	{
#if !defined (VOSD_NO_FIN)
	int _op_block_origin = 0;
#endif
	FIN_MT (scheduler_TCP_rt_ttf ());

		{


		FSM_ENTER ("scheduler_TCP_rt_ttf")

		FSM_BLOCK_SWITCH
			{
			/*---------------------------------------------------------*/
			/** state (init) enter executives **/
			FSM_STATE_ENTER_FORCED_NOLABEL (0, "init", "scheduler_TCP_rt_ttf [init enter execs]")
				FSM_PROFILE_SECTION_IN ("scheduler_TCP_rt_ttf [init enter execs]", state0_enter_exec)
				{
				// Get rtt from links delay
				l11_id = op_id_from_name(0, OPC_OBJTYPE_LKDUP, "wkstn_0 <-> loss_queue_0");
				l12_id = op_id_from_name(0, OPC_OBJTYPE_LKDUP, "server_0 <-> loss_queue_3");
				l21_id = op_id_from_name(0, OPC_OBJTYPE_LKDUP, "wkstn_1 <-> loss_queue_0");
				l22_id = op_id_from_name(0, OPC_OBJTYPE_LKDUP, "server_1 <-> loss_queue_2");
				op_ima_obj_attr_get (l11_id, "delay",&d11);
				op_ima_obj_attr_get (l12_id, "delay",&d12);
				op_ima_obj_attr_get (l21_id, "delay",&d21);
				op_ima_obj_attr_get (l22_id, "delay",&d22);
				printf("d11 = %f, d12 = %f, d21 = %f, d22 = %f\n", d11, d12, d21, d22);
				rtt_c1 = 2 * (d11 + d12);
				rtt_c2 = 2 * (d21 + d22);
				printf("rtt_c1 = %f, rtt_c2 = %f\n", rtt_c1, rtt_c2);
				
				// Get queue id 
				my_id = op_topo_parent(op_id_self()); // op_id_from_name(0, OPC_OBJMTYPE_NODE, "loss_queue");
				// middle router id
				bottleneck_id = op_id_from_name(0, OPC_OBJTYPE_NODE_FIX, "loss_queue_2");
				app_id = op_id_from_name(0, OPC_OBJTYPE_NODE_FIX, "application");
				
				printf("Queue ID: %d, Bottleneck ID: %d\n", my_id, bottleneck_id);
				
				read_routing_table ();
				for(i = 0; i < RT_SIZE; i++){
					// fscanf(file, "%d", &table[j]);
					printf("id %d: port %d\n", i, routing_table[i]);
				}
				i = 0;
				
				
				// Get base string for filenames
				op_ima_obj_attr_get (my_id, "res_path",&fbase_str);
				
				// Algorithm number (read from node attribute)
				//op_ima_obj_attr_get (my_id, "queue.Algorithm Number",&alg_num);
				op_ima_obj_attr_get (app_id, "Algorithm No",&alg_num);
				
				// Read recommended flag and other red parameters
				op_ima_obj_attr_get (my_id, "queue.Recommended RED",&recommended_red);
				printf("Recommended = %d\n", recommended_red);
				op_ima_obj_attr_get (my_id, "queue.RED min th",&min_th);
				op_ima_obj_attr_get (my_id, "queue.RED max p",&max_p);
				op_ima_obj_attr_get (my_id, "queue.Gentle Flag",&gentle_flag);
				op_ima_obj_attr_get (my_id, "queue.Feng Flag",&feng);
				//op_ima_obj_attr_get (my_id, "queue.Sally Flag",&sally);
				op_ima_obj_attr_get (app_id, "Sally Bool",&sally);
				
				
				// Smoothing flag for queue size (0 = no smoothing, 1 = smoothing)
					//smoothing = 1;
				op_ima_obj_attr_get (my_id, "queue.Smoothing Flag",&smoothing);
				
				// Get traffic dist
				// op_ima_obj_attr_get (my_id, "generator.Packet Interarrival Time",&bg_dist);
				//bg_iat = oms_dist_outcome(bg_dist);
				
				
				
				// BEGIN: Inicialización de parámetros
				
				c1_stop_loss = 0;
				c2_stop_loss = 0;
				red_count = -1;
				
				outcome4_instance = 0;
				
				feng_status = 3;
				alpha_feng = 3;
				beta_feng = 2;
				if (feng){
				max_p = 0.02; // src: ns3 implementation
				}
				
				alpha_ared = 0.01;
				beta_ared = 0.9;
				interval = 0.5;
				ared_prevtime = 0.0;
				target_delay = 0.005;
				// Idealmente link cap deberia leerse de la "línea" (actualmente 1/service_time)
				link_cap = 100000000/12000; // Asume C=1e9 y mss = 1500 *8 = 12000. Resultado esta en pkts/s
				
				if (sally){
					max_p = 0.02; // src: ns3 implementation
				}
				
				min_th = 5;
				if(min_th < target_delay*link_cap/2){
					min_th = target_delay*link_cap/2;
				}
				
				max_th = 3*min_th;
				
				cur_qsize = 0;
				if (feng || sally) {	
				    //w_q = 1 - exp(-1/link_cap);
					w_q = 0.002;
				} else {
					//w_q = 1 - exp(-1/link_cap);
					w_q = 0.002;  		 // RED avg queue size filter parameter
					//w_q = 0.001;
				}
				//s_red = 0.000000001; // tx time for 1 Gbps links connected to queue
				s_red = 1/link_cap;
				idle_stamp = 0;     // RED parameter
				contador_test = 0;
				increase_debt = 0;
				outcome = 5; // invalido
				drop_debt0 = 0;
				drop_debt1 = 0;
				drop_debt2 = 0;
				drop_debt3 = 0;
				nxt_idx0 = 0;
				nxt_idx1 = 0;
				nxt_idx2 = 0;
				nxt_idx3 = 0;
				last_ok0 = 0;
				last_ok1 = 0;
				last_ok2 = 0;
				last_ok3 = 0;
				last_lost0 = 0;
				last_lost1 = 0;
				last_lost2 = 0;
				last_lost3 = 0;
				cur_seq = 1;
				droppable = 1;
				repetition = 0;
				
				// Anti-timeout registry initialization
				L = 500; //30 previo
				for (i = 0; i < L; i = i + 1){ 
					drop_reg0[i] = 0;
					drop_reg1[i] = 0;
					drop_reg2[i] = 0; 
					drop_reg3[i] = 0;
					//printf("printing drop_reg[%d]: %d\n", i, drop_reg1[i]);
				}
				
				lpdf_c1_cnt = 0;
				lpdf_c2_cnt = 0;
				lpdf_limit = 4;
				
				// END: Inicialización de parámetros
				
				// BEGIN: Initialize files that will be saved in opnet_res folder
				
				get_file_str("loss_pdf.txt");
				loss_pdf_file = fopen(files_str,"a");
				fprintf(loss_pdf_file, "newdata\n");
				
				// Save parameters in txt file
				get_file_str("params.txt");
				params_file = fopen(files_str,"a");
				fprintf(params_file, "newdata\n");
				fprintf(params_file, "%d\n", alg_num);
				fprintf(params_file, "%f %f\n", rtt_c1, rtt_c2);
				fprintf(params_file, "%s\n", bg_dist);
				fprintf(params_file, "%d %d %f %f %d\n", smoothing, recommended_red, min_th, max_p, gentle_flag); //smoothing, rec_red, min_th, max_p, gentle_flag
				fprintf(params_file, "%f %f %d %d\n", w_q, target_delay, feng, sally);
				
				get_file_str("loss_data.txt");
				loss_file = fopen(files_str,"a");
				fprintf(loss_file, "newdata\n");
				
				get_file_str("remdebt.txt");
				remaining_debt_file = fopen(files_str,"a");
				fprintf(remaining_debt_file, "newdata\n");
				
				get_file_str("total.txt");
				total_file = fopen(files_str,"a");
				fprintf(total_file, "newdata\n");
				get_file_str("qstats.txt");
				qstats_file = fopen(files_str,"a");
				fprintf(qstats_file, "newdata\n");
				
				
				get_file_str("destroyed.txt");
				destroyed_file = fopen(files_str,"a");
				fprintf(destroyed_file, "newdata\n");
				fprintf(destroyed_file, "0 0.0 0\n");
				get_file_str("destroyed0.txt");
				destroyed0_file = fopen(files_str,"a");
				fprintf(destroyed0_file, "newdata\n");
				fprintf(destroyed0_file, "0 0.0 0\n");
				
				
				// END: initialize files in opnet_res
				
				//fp = fopen("C:\\packets.txt","w+");
				//fp_loss = fopen("C:\\packets_lossed.txt","w+");
				//fp64 = fopen("C:\\pk_id.txt","w+");
				//fp_aggr = fopen("C:\\aggressivity.txt","w+");
				//destroyed_file = fopen("C:\\destroyed.txt","w+");
				//destroyed0_file = fopen("C:\\destroyed0.txt","w+");
				debt_debug_file = fopen("C:\\debt_debug.txt","w+");
				link_output_file = fopen("C:\\link_output.txt","w+");
				qdata_file = fopen("C:\\qdata.txt","w+");
				main_loss_file = fopen("C:\\main_loss.txt","w+");
				
				queue_objid = op_id_self (); // op_topo_child (node_objid, OPC_OBJTYPE_QUEUE, 0);
				node_id = op_topo_parent (queue_objid);
				reserved_time = 0;
				// service_time = 0.0001168; // 0.00001168 <-- 1e9 b/s
				//service_time = 0.00000001; // 0.00000001 <-- 100 Mbps  // 0.000000001 <-- 1e9 b/s 
				service_time = 1/(link_cap*12000);
				//subq_size = 120;
				threshold = 0.2; //antes 0.2, en test = 0.0
				aggr_coef = 0.1;
				printf("Queue Total Size = %d, Threshold = %f, Agressivity Coefficient = %f\n", subq_size, threshold, aggr_coef);
				
				intrinsic_loss = 0.00;
				lambda = 1.0;
				fprintf(params_file, "%f \n", intrinsic_loss);
				
				flag_ttf = 0;
				var_cnt_c1 = 0;
				var_cnt_c2 = 0;
				dvar_c1 = 0;
				dvar_c2 = 0;
				d_debt_c1 = 0;
				nd_debt_c1 = 0;
				d_debt_c2 = 0;
				nd_debt_c2 = 0;
				
				last_q_record = 0;
				dt_q = 0.1;
				delay_S1 = 0;
				delay_S2 = 0;
				delay_W1 = 0;
				delay_W2 = 0;
				rtt1 = 0;
				rtt2 = 0;
				last_rtt = 0.1;
				rtt_data = 0;
				pkt_loss1 = 0;
				pkt_loss2 = 0;
				pkt_total1 = 0;
				pkt_total2 = 0;
				prev_seq1 = 0;
				prev_seq2 = 0;
				intr_loss_c1 = 0;
				intr_loss_c2 = 0;
				q_loss_c1 = 0;
				q_loss_c2 = 0;
				fq_loss_c1 = 0;
				fq_loss_c2 = 0;
				debt_loss_c1 = 0;
				debt_loss_c2 = 0;
				/*
				subq_comp_attr_objid = op_topo_child (queue_objid, OPC_OBJTYPE_COMP, 0);
				subq_objid = op_topo_child (subq_comp_attr_objid, OPC_OBJTYPE_SUBQ, 0);
				op_ima_obj_attr_get (subq_objid, "pk capacity", &subq_size);
				printf("ObjID queue: %d, ObjID_comp: %d, ObjID subqueue: %d, size: %d\n", queue_objid, subq_comp_attr_objid, subq_objid, (int) subq_size);
				
				*/
				op_ima_obj_attr_get (node_id, "queue size", &subq_size);
				
				
				printf("ObjID queue: %d, size: %d\n", node_id, subq_size);
				
				cnt_total_in = 0;
				cnt_total_out = 0;
				cnt_total_destroyed = 0;
				
				fact_conv = 1000000.0;
				
				qsize_sample = pow(2.0, 3.0);
				printf("Pow test, 2^3 = %f\n", qsize_sample);
				
				printf("exp test = exp(3) = %f\n", exp(3));
				printf("min_th = %f, max_th = %f, subq_size = %d, wq = %f\n", min_th, max_th, subq_size, w_q);
				printf("alfa_feng = %f, beta_feng = %f, alfa_ared = %f, beta_ared = %f, interval = %f\n", alpha_feng, beta_feng, alpha_ared, beta_ared, interval);
				
				printf("my: %d, sally = %d, alg = %d\n", my_id, sally, alg_num);
				}
				FSM_PROFILE_SECTION_OUT (state0_enter_exec)

			/** state (init) exit executives **/
			FSM_STATE_EXIT_FORCED (0, "init", "scheduler_TCP_rt_ttf [init exit execs]")


			/** state (init) transition processing **/
			FSM_TRANSIT_FORCE (1, state1_enter_exec, ;, "default", "", "init", "idle", "tr_0", "scheduler_TCP_rt_ttf [init -> idle : default / ]")
				/*---------------------------------------------------------*/



			/** state (idle) enter executives **/
			FSM_STATE_ENTER_UNFORCED (1, "idle", state1_enter_exec, "scheduler_TCP_rt_ttf [idle enter execs]")
				FSM_PROFILE_SECTION_IN ("scheduler_TCP_rt_ttf [idle enter execs]", state1_enter_exec)
				{
				if (PKTIN){
					
					increase_debt = 0;
					outcome = 5;
					flag_ttf = 0;
					port = op_intrpt_strm ();
					pkt = op_pk_get (port);
					cnt_total_in++;		
					time_stamp = op_pk_creation_time_get (pkt);
					op_pk_nfd_access(pkt, "destination", &dest_addr);
						
					// Get seq number for future use
					// if (!BG){
						op_pk_nfd_get_pkt (pkt, "encapsulation", &extract_pkt);
						op_pk_nfd_get_pkt (extract_pkt, "data", &tcp_pkt);
						op_pk_nfd_access (tcp_pkt, "fields", &fields_tcp);
						op_pk_nfd_set_pkt (extract_pkt, "data", tcp_pkt);
						op_pk_nfd_set_pkt (pkt, "encapsulation", extract_pkt);
					//}
					
					if (SERVER){ // pérdida solo a puertos impares (del server)
					//fprintf(fp, "%d %d %4.12f %4.12f\n", 0, port, op_sim_time(), (double) service_time*op_pk_total_size_get(pkt) ); // ((double)op_pk_total_size_get(pkt)) op_pk_id(pkt), 
					//	direction-^  ^-(in/out) port sim_time duration
					
						switch (port){
							case 1:
							delay_S1 = op_sim_time() - time_stamp;			
							pkt_total1++;	
							break;
							
							case 3:
							delay_S2 = op_sim_time() - time_stamp;
							pkt_total2++;
							break;
							
							case 4:
							break;
							
							// default:
							// printf("SERVER puerto imposible port = %d, error\n", port);
						}
					}	
					if (WKSTN){	
					
						switch (port){
							case 0:
							delay_W1 = op_sim_time() - time_stamp;
							rtt1 = 2 * (delay_W1 + delay_S1);			
							break;
							
							case 2:
							delay_W2 = op_sim_time() - time_stamp;
							rtt2 = 2 * (delay_W2 + delay_S2);			
							break;
							
							// default:
							// printf("WKSTN puerto imposible port = %d, error\n", port);
						}
					}
					
					// if (BG){
					if (0){
						if (op_dist_uniform(1.0) > intrinsic_loss){
							if (op_subq_stat (subq_index, OPC_QSTAT_PKSIZE) < subq_size){
								last_rtt = 0.1; // Por cambiar?, corresponde al rtt del trafico de fondo, necesario para calcular var_loss
								// INICIO: Calculo probabilidad de algoritmo **********  TTF ALGORITHM **************//	
								
								/* Check if queue size will be averaged (smoothed) or not*/
								if (smoothing) {
									qsize_sample = op_subq_stat (subq_index,OPC_QSTAT_PKSIZE);
									//fprintf(qdata_file, "%d %f %f %f 0 %f\n", qsize_sample, cur_qsize, op_sim_time(), max_p, idle_stamp);
									if (qsize_sample == 0) {
										//idle_stamp = (idle_stamp < 0)?op_sim_time():idle_stamp;
										idle_power = (op_sim_time()-idle_stamp)/s_red;
										cur_qsize = pow((1-w_q),idle_power) * cur_qsize;
									} else {
										//idle_stamp = -1;
										cur_qsize = cur_qsize + w_q*(qsize_sample-cur_qsize);
									}					
								} else {					
									cur_qsize = op_subq_stat (subq_index,OPC_QSTAT_PKSIZE);
								}
								
								// After updating avg qsize, update maxp if feng's adaptive is active.
								if (feng){
									if ((min_th <  cur_qsize) && (cur_qsize < max_th)) {
										feng_status = 2;
									} else if ((cur_qsize < min_th) && (feng_status !=1)) {
										feng_status = 1;
										max_p = max_p / alpha_feng;
									} else if ((cur_qsize > max_th) && (feng_status !=3)) {
										feng_status = 3;
										max_p = max_p * beta_feng;
									} 
								} else if (sally){
									if ((op_sim_time() - ared_prevtime) > interval) {
										if ((cur_qsize > (min_th + 0.6*(max_th-min_th))) && (max_p <= 0.5)) {
											max_p = max_p + alpha_ared;
											ared_prevtime = op_sim_time();
										} else if ((cur_qsize < (min_th +0.4*(max_th-min_th))) && (max_p >= 0.01)) {
											max_p = max_p * beta_ared;
											ared_prevtime = op_sim_time();
										}							
									}
								}
								
								
								//red_loss = (double) (cur_qsize/((double) subq_size) - threshold)/(1 - threshold);
								//red_loss = (red_loss < 0)?0:red_loss;
								
								if (recommended_red){
									red_loss = get_rec_red_loss();
								} else {
									red_loss = get_ttf_red_loss();
								}
									
								var_loss = get_ttf_var_loss();
								//var_loss = (double) (aggr_coef/last_rtt)*(aggr_coef/last_rtt)*red_loss;
								
								// Probability adjustment according to current algorithm
								switch (alg_num){
									case 1:
										// DropTail
										var_loss = 0;
										break;
									
									case 2:
										// RED
										var_loss = red_loss;
										break;
						
									case 3:
										// TTF, do nothing						
										break;
									
									default:
										printf("invalid alg number\n");				
								}
				
								// FIN: Calculo probabilidad de algoritmo TTF
								if ((cur_qsize > (!recommended_red) * threshold * subq_size) && (op_dist_uniform(1.0) <= var_loss)){
									op_pk_destroy(pkt);	
									cnt_total_destroyed++;
									red_count = 0;
								} else {
									// Save subqueue stats
									if ((op_sim_time()-last_q_record) > dt_q){
										pkts_inq = op_subq_stat (0, OPC_QSTAT_PKSIZE); // number of pkts in subq 
										q_delay = op_subq_stat (0, OPC_QSTAT_DELAY); // number of pkts in subq
										fprintf(qstats_file, "%d %f %f %f %f\n", pkts_inq, cur_qsize, q_delay, op_sim_time(), max_p);
										last_q_record = op_sim_time();
									}
									
									// Insert in queue
									op_subq_pk_insert (subq_index, pkt, OPC_QPOS_TAIL);
									reserved_time = max(op_sim_time(), reserved_time) + service_time*op_pk_total_size_get(pkt); // total_size_get in bits
									// printf("queueing delay = %f\n", reserved_time - op_sim_time());
									op_intrpt_schedule_self (reserved_time, subq_index);
								}
							} else {
								op_pk_destroy(pkt);
								cnt_total_destroyed++;
							}
						} else {
							op_pk_destroy(pkt);
							cnt_total_destroyed++;
						}
					}
				
					
					if ((SERVER) && (!flag_ttf)){ // toward workstation (data)
						subq_index = 0; // (port-1)>>1;
						contador_test++;
						//printf("SERVER: contador_test = %d\n", contador_test);
						
						outcome4_instance = 0;
						
						// INICIO: Ajusto parámetros según la conexión
						switch (dest_addr){
								case 0:
									//drop_reg = drop_reg0;
									for (i = 0;i < L; i = i + 1)
										{
											drop_reg[i] = drop_reg0[i];
										}
									last_ok = last_ok0;
									nxt_idx = nxt_idx0;
									drop_debt = drop_debt0;
									last_lost = last_lost0;
									//printf("nxt_idx = %d\n", nxt_idx);
									break;
						
								case 2:
									//drop_reg = drop_reg1;
									for (i = 0;i < L; i = i + 1)
										{
											drop_reg[i] = drop_reg1[i];
										}
									last_ok = last_ok1;
									nxt_idx = nxt_idx1;
									drop_debt = drop_debt1;
									last_lost = last_lost1;
									//printf("nxt_idx = %d\n", nxt_idx);
									break;
									
								case 4:
									//drop_reg = drop_reg0;
									for (i = 0;i < L; i = i + 1)
										{
											drop_reg[i] = drop_reg2[i];
										}
									last_ok = last_ok2;
									nxt_idx = nxt_idx2;
									drop_debt = drop_debt2;
									last_lost = last_lost2;
									//printf("nxt_idx = %d\n", nxt_idx);
									break;
						
								case 6:
									//drop_reg = drop_reg1;
									for (i = 0;i < L; i = i + 1)
										{
											drop_reg[i] = drop_reg3[i];
										}
									last_ok = last_ok3;
									nxt_idx = nxt_idx3;
									drop_debt = drop_debt3;
									last_lost = last_lost3;
									//printf("nxt_idx = %d\n", nxt_idx);
									break;
									
								// default:
									// printf("port: %d (deberia ser 1 o 3)\n", port);				
						}
						// FIN: Ajusto parámetros según la conexión	
						
						
						// INICIO: Determino si el paquete es descartable para evitar 2x loss		
						if ((op_sim_time()<214.5 && op_sim_time()>213.2) && port == 1){
						 	printf("cur_seq-last_lost = %d, cur_seq = %d, last_lost = %d, time: %.12f\n", (cur_seq-last_lost), cur_seq, last_lost, op_sim_time());
						}
						
						cur_seq = fields_tcp->seq_num;
						droppable = 1;
						if (((cur_seq-last_lost) > 1460*3)|| ((cur_seq-last_lost) < 0) || (last_lost == 0)){
							might_drop = 1;			
						} else {
							might_drop = 0;
							droppable = 0;
						}
						if (might_drop)
						{
						
						if (cur_seq>last_ok){
							
							// Zona de crecimiento monótono -> no hay peligro de doble pérdida
							droppable = 1;
							// Actualizo last_ok
							switch (dest_addr){
								case 0:
									last_ok0 = cur_seq;
									break;				
								case 2:
									last_ok1 = cur_seq;
									break;
								case 4:
									last_ok2= cur_seq;
									break;				
								case 6:
									last_ok3 = cur_seq;
									break;
											
								// default:
									// printf("port: %d (deberia ser 1 o 3)\n", port);				
							}
											
						} else {
							
							repetition = 0;
						
							// Zona de peligro, se debe chequear posible doble pérdida
							for (i = 1; i < (nxt_idx + 1); i = i + 1){
								//printf("Checking from nxt_idx-1 to 0\n");
								//printf("nxt_idx = %d, nxt_idx-i = %d\n", nxt_idx, (nxt_idx-i));
								//Chequeo desde el siguiente indice - 1 (ultimo registro) hasta el inicio
							
								if (cur_seq == drop_reg[nxt_idx-i]){
									repetition = 1;
									break;
								} else {
									repetition = 0;
								}
							}
									
							if (repetition == 0){
							
								for (i = 0; i < (L - nxt_idx); i = i + 1){
									//printf("Checking from L-1 to nxt_idx\n");
									//printf("nxt_idx = %d, L-1 - i = %d\n", nxt_idx, (L-1-i));
									//Chequeo desde el final hasta el siguiente indice
									
									if (cur_seq == drop_reg[L-1 - i]){
										repetition = 1;
										break;
									} else
										repetition = 0;	
								}
							}
									
							// Basado en lo anterior, determino si es descartable o no
							if (repetition)
								droppable = 0;
							else
								droppable = 1;
						}
						}
						// FIN: Determino si el paquete es descartable para evitar 2x loss
							
						// INICIO: Calculo probabilidad de algoritmo TTF
						/*
						switch (port){
								case 1:
									op_pk_nfd_access(pkt, "measure RTT", &rtt1);
									// printf("RTT 1 = %f\n", ((double) rtt1)/fact_conv);
									last_rtt = ((double) rtt1)/fact_conv;
									break;
								case 3:
									op_pk_nfd_access(pkt, "measure RTT", &rtt2);
									// printf("RTT 2 = %f\n", ((double) rtt2)/fact_conv);
									last_rtt = ((double) rtt2)/fact_conv;
									break;
								// default:
									// printf("SERVER puerto imposible port = %d, error\n", port);
						}
						*/
						
						op_pk_nfd_access(pkt, "measure RTT", &rtt_data);		
						//printf("RTT data = %f\n", ((double) rtt_data));
						//printf("RTT data/fact = %f\n", ((double) rtt_data)/fact_conv);
						last_rtt = ((double) rtt_data)/fact_conv;
						
							
						// **********  TTF ALGORITHM **************//
						/* Check if queue size will be averaged (smoothed) or not*/
						if (smoothing) {
							qsize_sample = op_subq_stat (subq_index,OPC_QSTAT_PKSIZE);
							//fprintf(qdata_file, "%d %f %f %f 1 %f\n", qsize_sample, cur_qsize, op_sim_time(), max_p, idle_stamp);
							if (qsize_sample == 0){
								//idle_stamp = (idle_stamp < 0)?op_sim_time():idle_stamp;
								idle_power = (op_sim_time()-idle_stamp)/s_red;
								cur_qsize = pow((1-w_q),idle_power) * cur_qsize;
							} else {
								//idle_stamp = -1;
								cur_qsize = cur_qsize + w_q*(qsize_sample-cur_qsize);
							}
						} else {					
							cur_qsize = op_subq_stat (subq_index,OPC_QSTAT_PKSIZE);
						}
						
						// After updating avg qsize, update maxp if feng's adaptive is active.
						if (feng){
							if ((min_th <  cur_qsize) && (cur_qsize < max_th)){
								feng_status = 2;
							} else if ((cur_qsize < min_th) && (feng_status !=1)){
								feng_status = 1;
								max_p = max_p / alpha_feng;
							} else if ((cur_qsize > max_th) && (feng_status !=3)){
								feng_status = 3;
								max_p = max_p * beta_feng;
							} 
						} else if (sally){
							if ((op_sim_time() - ared_prevtime) > interval) {
								if ((cur_qsize > (min_th + 0.6*(max_th-min_th))) && (max_p <= 0.5)) {
									max_p = max_p + alpha_ared;
									ared_prevtime = op_sim_time();
								} else if ((cur_qsize < (min_th +0.4*(max_th-min_th))) && (max_p >= 0.01)) {
									max_p = max_p * beta_ared;
									ared_prevtime = op_sim_time();
								}							
							}			
						}
						
						// red_loss = (double) (cur_qsize/((double) subq_size) - threshold)/(1 - threshold);
						// red_loss = (red_loss < 0)?0:red_loss;
						// red_loss = red_loss / 5;
						if (recommended_red){
							red_loss = get_rec_red_loss();
						} else {
							red_loss = get_ttf_red_loss();
						}
					
						var_loss = get_ttf_var_loss();
						fprintf(main_loss_file, "%f %f %f\n", op_sim_time(), var_loss, red_loss);
						//var_loss = (double) (aggr_coef/last_rtt)*(aggr_coef/last_rtt)*red_loss;
					
						// printf("Red Loss = %f, Queue Occupied Size = %f, Actual Loss = %f, Threshold = %f, Queue Total Size = %d\n", red_loss, op_subq_stat (subq_index,OPC_QSTAT_PKSIZE), var_loss, threshold, subq_size);
						//fprintf(fp_aggr, "%d %4.12f %4.0f %4.12f %d\n", port, red_loss, op_subq_stat (subq_index,OPC_QSTAT_PKSIZE), var_loss, port);
						// inicio test
						//var_loss = intrinsic_loss*((0.15/last_rtt)*(0.15/last_rtt)-1);
						//var_loss = (var_loss<0)?0:var_loss;
						//var_loss = 0;
						//printf("var_loss = %.12f, port = %d\n", var_loss, port);
						// fin test
						switch (alg_num){
								case 1:
									// DropTail
									var_loss = 0;
									break;
									
								case 2:
									// RED
									var_loss = red_loss;
									break;
						
								case 3:
									// TTF, do nothing						
									break;
													
								default:
									printf("invalid alg number\n");				
						}
						// FIN: Calculo probabilidad de algoritmo TTF
						
						// INICIO: determinar "outcome"
						if (drop_debt>0){
							//printf("DROP DEBT >0\n");
							if (droppable){
								// Reduce debt
								switch (dest_addr){
									case 0:
										drop_debt0 = drop_debt0 - 1;
										d_debt_c1++;
										break;				
									case 2:
										drop_debt1 = drop_debt1 - 1;
										d_debt_c2++;
										break;
									case 4:
										drop_debt2 = drop_debt2 - 1;
										//d_debt_c1++;
										break;				
									case 6:
										drop_debt3 = drop_debt3 - 1;
										//d_debt_c2++;
										break;
									// default:
										// printf("port: %d (deberia ser 1 o 3)\n", port);				
								}
								outcome = 0;
							} else {
								if (op_subq_stat (subq_index, OPC_QSTAT_PKSIZE) >= subq_size){
									// Nothing you can do, must drop pkt cause queue is full
									outcome = 2;	
								} else {
									// Insert into queue
									outcome = 4;
									outcome4_instance = 1;
								}
								// Determine if debt should be increased
								if (op_dist_uniform(1.0) <= intrinsic_loss){
									increase_debt = 1;					
								} else {
									if (op_subq_stat (subq_index, OPC_QSTAT_PKSIZE) < subq_size){						
										if ((cur_qsize >=  (!recommended_red) * threshold * subq_size) && (op_dist_uniform(1.0) <= var_loss)){
											increase_debt = 1;						
										}
									} 
								}
								if (port == 1){
									nd_debt_c1++;
								} else if (port == 3){
									nd_debt_c2++;
								}
							}
						} else {
							//printf("DROP DEBT= %d\n", drop_debt);
							if (op_dist_uniform(1.0) <= intrinsic_loss){
								if (droppable){
									outcome = 1;
								}
								else{
									increase_debt = 1;
									outcome = 4;
									outcome4_instance = 2;
								}
							} else {
								if (op_subq_stat (subq_index, OPC_QSTAT_PKSIZE) >= subq_size){ // == deberia bastar + falta agregar el tamaño como parametro
									outcome = 2;
								} else {
									//printf("threshold factor = %f\n", ((!recommended_red) * threshold * subq_size));
									if ((cur_qsize >= (!recommended_red) * threshold * subq_size) && (op_dist_uniform(1.0) <= var_loss)){
										if (droppable){
											outcome = 3;
											red_count = 0;
										} else {
											outcome = 4;
											outcome4_instance = 3;
											increase_debt = 1;
										}
										
										if (port == 1){						
											var_cnt_c1++;
											if (droppable){
												dvar_c1++;
											}
										} else if (port == 3){
											var_cnt_c2++;
											if (droppable){
												dvar_c2++;
											}
										}
										
									} else {
										if (port == 1){						
											var_cnt_c1++;
											if (droppable){
												dvar_c1++;
											}
										} else if (port == 3){
											var_cnt_c2++;
											if (droppable){
												dvar_c2++;
											}
										}
										
										outcome = 4;
										outcome4_instance = 4;
									}				
								}
							}
						}
						
						
						// Update stop sequence numbers once
						op_ima_obj_attr_get (my_id, "queue.c1_stop",&c1_stop_loss);
						op_ima_obj_attr_get (my_id, "queue.c2_stop",&c2_stop_loss);
						
						
						if ((cur_seq >= c1_stop_loss) && (port == 1) && (c1_stop_loss != 0)) {
							printf("c1 boolean true, not dropping pkts, time: %f, stop at %d\n", op_sim_time(), c1_stop_loss);
							increase_debt = 0;
							outcome = 4;
							outcome4_instance = 5;
						}
						if ((cur_seq >= c2_stop_loss) && (port == 3) && (c2_stop_loss != 0)) {		
							printf("c2 boolean true, not dropping pkts, time: %f stop at %d\n", op_sim_time(), c2_stop_loss);
							increase_debt = 0;
							outcome = 4;
							outcome4_instance = 6;
						}
						// FIN: determinar "outcome"
						
						// Save loss_pdf data
						if (port == 1) {
							if (lpdf_c1_cnt >=4){
								lpdf_c1_cnt = 0;
								fprintf(loss_pdf_file, "%f %f %d %f %d %d\n", cur_qsize, var_loss, cur_seq, op_sim_time(), port, outcome);
							} else {
								lpdf_c1_cnt++;
							}						
						} else if (port == 3) {
							if (lpdf_c2_cnt >=4){
								lpdf_c2_cnt = 0;
								fprintf(loss_pdf_file, "%f %f %d %f %d %d\n", cur_qsize, var_loss, cur_seq, op_sim_time(), port, outcome);
							} else {
								lpdf_c2_cnt++;
							}	
						}
						
						//fprintf(loss_pdf_file, "%f %f %d %f %d %d\n", cur_qsize, var_loss, cur_seq, op_sim_time(), port, outcome);
						
						
						// INICIO: incrementar deuda si es necesario
						if (increase_debt){
							//printf("INCREASING DEBT\n");
							switch (dest_addr){
								case 0:
									//drop_debt0 = drop_debt0 + 1;
									drop_debt0 = 1;
									break;				
								case 2:
									//drop_debt1 = drop_debt1 + 1;
									drop_debt1 = 1;
									break;
								case 4:
									//drop_debt0 = drop_debt0 + 1;
									drop_debt2 = 1;
									break;				
								case 6:
									//drop_debt1 = drop_debt1 + 1;
									drop_debt3 = 1;
									break;
								// default:
									// printf("port: %d (deberia ser 1 o 3)\n", port);				
								}	
						}
						// FIN: incrementar deuda si es necesario
							
						// INICIO: ejecutar accion en fn de "outcome"
						//printf("Outcome = %d\n", outcome);
						if (outcome == 0 || outcome == 1 || outcome == 2 || outcome == 3){
							// Pkt is droppable, 0: drop_debt, 1: intrinsic_loss, 2: queue is full, 3: algorithm loss
						
							// Before destroying, save data and add to drop_reg
							switch (dest_addr){
								case 0:
									if (outcome == 3){
										q_loss_c1++;
									} else if (outcome == 2){ 
										fq_loss_c1++;
									} else if (outcome == 1){
										intr_loss_c1++;
									} else if (outcome == 0){
										debt_loss_c1++;
									}	
									fprintf(destroyed0_file, "%d %4.12f %d\n", fields_tcp->seq_num, op_sim_time(), outcome);
									drop_reg0[nxt_idx0] = cur_seq;
									last_lost0 = cur_seq;
									// drop_reg00[nxt_idx0] = cur_seq + 1460;
									// drop_reg01[nxt_idx0] = cur_seq + 1460*2;
									// drop_reg02[nxt_idx0] = cur_seq + 1460*3;
									nxt_idx0 = (nxt_idx0 < L-1) ? (nxt_idx0 + 1) : 0;
									//printf("nxt_idx0 was updated to: %d\n", nxt_idx0);
									break;
							
								case 2:
									if (outcome == 3){
										q_loss_c2++;
									} else if (outcome == 2){
										fq_loss_c2++;
									} else if (outcome == 1){
										intr_loss_c2++;
									} else if (outcome == 0){
										debt_loss_c2++;
									}
									fprintf(destroyed_file, "%d %4.12f %d\n", fields_tcp->seq_num, op_sim_time(), outcome);
									drop_reg1[nxt_idx1] = cur_seq;
									last_lost1 = cur_seq;
									nxt_idx1 = (nxt_idx1 < L-1) ? (nxt_idx1 + 1) : 0;
									//printf("nxt_idx1 was updated to: %d\n", nxt_idx1);
									break;
									
								case 4:
									/*
									if (outcome == 3){
										q_loss_c1++;
									} else if (outcome == 2){ 
										fq_loss_c1++;
									} else if (outcome == 1){
										intr_loss_c1++;
									} else if (outcome == 0){
										debt_loss_c1++;
									}
									fprintf(destroyed0_file, "%d %4.12f %d\n", fields_tcp->seq_num, op_sim_time(), outcome);
									*/
									drop_reg2[nxt_idx2] = cur_seq;
									last_lost2 = cur_seq;
									nxt_idx2 = (nxt_idx2 < L-1) ? (nxt_idx2 + 1) : 0;
									//printf("nxt_idx0 was updated to: %d\n", nxt_idx0);
									break;
							
								case 6:
									/*
									if (outcome == 3){
										q_loss_c2++;
									} else if (outcome == 2){
										fq_loss_c2++;
									} else if (outcome == 1){
										intr_loss_c2++;
									} else if (outcome == 0){
										debt_loss_c2++;
									}
									fprintf(destroyed_file, "%d %4.12f %d\n", fields_tcp->seq_num, op_sim_time(), outcome);
									*/
									drop_reg3[nxt_idx3] = cur_seq;
									last_lost3 = cur_seq;
									nxt_idx3 = (nxt_idx3 < L-1) ? (nxt_idx3 + 1) : 0;
									//printf("nxt_idx1 was updated to: %d\n", nxt_idx1);
									break;
										
								// default:
									// printf("port: %d (deberia ser 1 o 3)\n", port);				
							}
											
							// Destroy packet (cause: drop_debt )
							if (op_pk_total_size_get (pkt) == 12064){
							// printf("Packet Destroyed size: %d bits\n", op_pk_total_size_get (pkt));
							} else {
							printf("WARNING: NON-12064-bit PACKET DESTROYED\nPacket Destroyed size: %d bits\n", op_pk_total_size_get (pkt));
							}
							op_pk_destroy(pkt);
							cnt_total_destroyed++;
							//fprintf(fp_loss, "%d %4.12f\n", port, op_sim_time());
							
						} else if (outcome == 4){
				
							if ((op_sim_time()-last_q_record) > dt_q){
								pkts_inq = op_subq_stat (0, OPC_QSTAT_PKSIZE); // number of pkts in subq 
								q_delay = op_subq_stat (0, OPC_QSTAT_DELAY); // number of pkts in subq
								fprintf(qstats_file, "%d %f %f %f %f\n", pkts_inq, cur_qsize, q_delay, op_sim_time(), max_p);
								last_q_record = op_sim_time();
							}
				
							//printf("Inserting pkt into queue\n");
							// Pkt will be inserted to queue (maybe no loss, or debt is increased because pkt should be dropped and is not droppable)
							op_subq_pk_insert (subq_index, pkt, OPC_QPOS_TAIL);
							reserved_time = max(op_sim_time(), reserved_time) + service_time*op_pk_total_size_get(pkt); // total_size_get in bits
							// printf("queueing delay = %f\n", reserved_time - op_sim_time());
							op_intrpt_schedule_self (reserved_time, subq_index);
							
						} else {
							printf("INVALID OUTCOME!!!\n");
						}			
						// FIN: ejecutar accion en fn de "outcome"	
						
						if (port == 3){
							fprintf(debt_debug_file, "%d %d %d %d %d %f %f %f %f %f %f %d %d\n", cur_seq, droppable, outcome, increase_debt, drop_debt, cur_qsize, var_loss, red_loss, aggr_coef, last_rtt, op_sim_time(), subq_size, outcome4_instance);
						}
						
					} else if (WKSTN) { // return to server (ACKs)
						contador_test++;
						//printf("WKSTN, contador_test = %d\n", contador_test);
						if (!flag_ttf){
						// op_pk_send(pkt, port+1);
						op_pk_send(pkt, routing_table[dest_addr]);
						cnt_total_out++;
						}
					}
				
				
				} else if(PKTOUT) {
					pkt = op_subq_pk_remove (op_intrpt_code (), OPC_QPOS_HEAD);
					
					if (op_pk_nfd_access(pkt, "destination", &dest_addr) == OPC_COMPCODE_FAILURE){
						printf("access failed!\n");		
						// dest_addr = 4;
					} 
					
					// printf("ROUTING: router: %d, destination: %d, output port: %d, time: %f\n", my_id, dest_addr, routing_table[dest_addr], op_sim_time());
					op_pk_send(pkt, routing_table[dest_addr]);
					
					if (my_id == bottleneck_id){
						fprintf(link_output_file, "%d %.8f %d\n", dest_addr, op_sim_time(), op_pk_total_size_get (pkt));
					}
					
					/*	
					if (routing_table[dest_addr] <= 3){
						op_pk_send(pkt, routing_table[dest_addr]);  // serviced queued packet (data)
						//fprintf(fp, "%d %d %4.12f %4.12f\n", 1, dest_addr+1, op_sim_time(), (double) service_time*op_pk_total_size_get(pkt) );
						// printf("less than 3\n");
						//op_pk_print(pkt);
						//printf("pkt total size = %d, out = %d\n",op_pk_total_size_get (pkt), dest_addr);
						fprintf(link_output_file, "%d %.8f %d\n", dest_addr, op_sim_time(), op_pk_total_size_get (pkt));
					} else {
						op_pk_send(pkt, 4);	
						//printf("pkt total size = %d, out = 4\n",op_pk_total_size_get (pkt));
						fprintf(link_output_file, "4 %.8f %d\n",  op_sim_time(), op_pk_total_size_get (pkt));
						// printf("more than 4\n");
					}
					*/
					
					cnt_total_out++;
					pkts_inq = op_subq_stat (subq_index,OPC_QSTAT_PKSIZE);
					//fprintf(qdata_file, "%d %f %f %f 0 %f\n", pkts_inq, cur_qsize, op_sim_time(), max_p, idle_stamp);
								
					if (pkts_inq == 0){
						idle_stamp = op_sim_time();
					}
				}
				}
				FSM_PROFILE_SECTION_OUT (state1_enter_exec)

			/** blocking after enter executives of unforced state. **/
			FSM_EXIT (3,"scheduler_TCP_rt_ttf")


			/** state (idle) exit executives **/
			FSM_STATE_EXIT_UNFORCED (1, "idle", "scheduler_TCP_rt_ttf [idle exit execs]")


			/** state (idle) transition processing **/
			FSM_PROFILE_SECTION_IN ("scheduler_TCP_rt_ttf [idle trans conditions]", state1_trans_conds)
			FSM_INIT_COND (FINISH)
			FSM_DFLT_COND
			FSM_TEST_LOGIC ("idle")
			FSM_PROFILE_SECTION_OUT (state1_trans_conds)

			FSM_TRANSIT_SWITCH
				{
				FSM_CASE_TRANSIT (0, 2, state2_enter_exec, ;, "FINISH", "", "idle", "fin", "tr_2", "scheduler_TCP_rt_ttf [idle -> fin : FINISH / ]")
				FSM_CASE_TRANSIT (1, 1, state1_enter_exec, ;, "default", "", "idle", "idle", "tr_1", "scheduler_TCP_rt_ttf [idle -> idle : default / ]")
				}
				/*---------------------------------------------------------*/



			/** state (fin) enter executives **/
			FSM_STATE_ENTER_UNFORCED (2, "fin", state2_enter_exec, "scheduler_TCP_rt_ttf [fin enter execs]")
				FSM_PROFILE_SECTION_IN ("scheduler_TCP_rt_ttf [fin enter execs]", state2_enter_exec)
				{
				/*
				fclose(fp);
				fclose(fp_loss);
				fclose(fp64);
				fclose(fp_aggr);
				*/
				fclose(debt_debug_file);
				fclose(link_output_file);
				
				//printf("loss 1: %d, loss 2: %d\n", pkt_loss1, pkt_loss2);
				printf("total 1: %d, total 2: %d\n", pkt_total1, pkt_total2);
				//printf("percent loss 1: %f, percent loss 2: %f\n", (double) pkt_loss1/pkt_total1, (double) pkt_loss2/pkt_total2);
				printf("totals: in: %d, out: %d, destroyed: %d, diff in-out: %d, limbo: %d\n", cnt_total_in, cnt_total_out, cnt_total_destroyed, cnt_total_in - cnt_total_out, cnt_total_in - cnt_total_out - cnt_total_destroyed);
				
				printf("\n last seq1: %d, last seq2: %d\n", prev_seq1, prev_seq2);
				printf("Intrisic loss c1 = %d\nIntrinsic loss c2 = %d\nQueue loss c1 = %d\nQueue loss c2 = %d\n", intr_loss_c1, intr_loss_c2, q_loss_c1, q_loss_c2);
				fprintf(loss_file, "%d %d %d %d %d %d %d %d\n", intr_loss_c1, intr_loss_c2, q_loss_c1, q_loss_c2, debt_loss_c1, debt_loss_c2, fq_loss_c1, fq_loss_c2);
				fprintf(total_file, "%d %d\n", pkt_total1, pkt_total2);
				printf("Debt loss c1 = %d\nDebt loss c2 = %d\n", debt_loss_c1, debt_loss_c2);
				fprintf(remaining_debt_file, "%d %d %d %d\n", drop_debt0, drop_debt1, var_cnt_c1, dvar_c1, d_debt_c1, nd_debt_c1, var_cnt_c2, dvar_c2, d_debt_c2, nd_debt_c2);
				
				}
				FSM_PROFILE_SECTION_OUT (state2_enter_exec)

			/** blocking after enter executives of unforced state. **/
			FSM_EXIT (5,"scheduler_TCP_rt_ttf")


			/** state (fin) exit executives **/
			FSM_STATE_EXIT_UNFORCED (2, "fin", "scheduler_TCP_rt_ttf [fin exit execs]")


			/** state (fin) transition processing **/
			FSM_TRANSIT_MISSING ("fin")
				/*---------------------------------------------------------*/



			}


		FSM_EXIT (0,"scheduler_TCP_rt_ttf")
		}
	}




void
_op_scheduler_TCP_rt_ttf_diag (OP_SIM_CONTEXT_ARG_OPT)
	{
	/* No Diagnostic Block */
	}




void
_op_scheduler_TCP_rt_ttf_terminate (OP_SIM_CONTEXT_ARG_OPT)
	{
#if !defined (VOSD_NO_FIN)
	int _op_block_origin = __LINE__;
#endif

	FIN_MT (_op_scheduler_TCP_rt_ttf_terminate ())

	if (1)
		{

		/* Termination Block */

		BINIT
		{
		fclose(fp);
		fclose(fp_loss);
		fclose(fp64);
		fclose(fp_aggr);
		fclose(loss_file);
		fclose(destroyed_file);
		fclose(destroyed0_file);
		fclose(total_file);
		fclose(params_file);
		fclose(qstats_file);
		}

		/* End of Termination Block */

		}
	Vos_Poolmem_Dealloc (op_sv_ptr);

	FOUT
	}


/* Undefine shortcuts to state variables to avoid */
/* syntax error in direct access to fields of */
/* local variable prs_ptr in _op_scheduler_TCP_rt_ttf_svar function. */
#undef fp
#undef fp_loss
#undef fp64
#undef fp_aggr
#undef debt_debug_file
#undef link_output_file
#undef loss_file
#undef destroyed_file
#undef destroyed0_file
#undef total_file
#undef params_file
#undef qstats_file
#undef loss_pdf_file
#undef remaining_debt_file
#undef qdata_file
#undef main_loss_file
#undef port
#undef pkt
#undef subq_objid
#undef queue_objid
#undef subq_comp_attr_objid
#undef subq_size
#undef node_id
#undef time_stamp
#undef tcp_pkt
#undef subq_index
#undef test_int
#undef test_index
#undef fields_ip
#undef ip_address
#undef dest_address
#undef reserved_time
#undef service_time
#undef rtt1
#undef rtt2
#undef last_rtt
#undef delay_S1
#undef delay_S2
#undef delay_W1
#undef delay_W2
#undef pkt_loss1
#undef pkt_loss2
#undef pkt_total1
#undef pkt_total2
#undef fields_tcp
#undef prev_seq1
#undef prev_seq2
#undef packet_format
#undef intrinsic_loss
#undef ip_id
#undef num_formatted_fields
#undef fmt_name
#undef threshold
#undef red_loss
#undef var_loss
#undef aggr_coef
#undef intr_loss_c1
#undef intr_loss_c2
#undef q_loss_c1
#undef q_loss_c2
#undef fq_loss_c1
#undef fq_loss_c2
#undef debt_loss_c1
#undef debt_loss_c2
#undef queue_id
#undef app_id
#undef app_defs_objid
#undef dest_pref_objid
#undef dest_pref_value
#undef cnt_total_in
#undef cnt_total_out
#undef cnt_total_destroyed
#undef dest_addr
#undef fact_conv
#undef extract_pkt
#undef flag_ttf
#undef drop_debt
#undef drop_debt0
#undef drop_debt1
#undef drop_debt2
#undef drop_debt3
#undef cur_seq
#undef last_ok
#undef last_ok0
#undef last_ok1
#undef last_ok2
#undef last_ok3
#undef drop_reg3
#undef drop_reg2
#undef drop_reg1
#undef drop_reg0
#undef drop_reg
#undef L
#undef i
#undef droppable
#undef nxt_idx
#undef nxt_idx0
#undef nxt_idx1
#undef nxt_idx2
#undef nxt_idx3
#undef repetition
#undef outcome
#undef increase_debt
#undef contador_test
#undef might_drop
#undef last_lost
#undef last_lost0
#undef last_lost1
#undef last_lost2
#undef last_lost3
#undef l11_id
#undef l12_id
#undef l21_id
#undef l22_id
#undef d11
#undef d12
#undef d21
#undef d22
#undef rtt_c1
#undef rtt_c2
#undef alg_num
#undef pkts_inq
#undef q_delay
#undef cur_qsize
#undef qsize_sample
#undef smoothing
#undef w_q
#undef s_red
#undef idle_stamp
#undef idle_power
#undef last_q_record
#undef dt_q
#undef my_id
#undef bg_dist
#undef bg_iat
#undef recommended_red
#undef gentle_flag
#undef min_th
#undef max_p
#undef fbase_str
#undef files_str
#undef alpha_feng
#undef beta_feng
#undef feng
#undef feng_status
#undef max_th
#undef target_delay
#undef sally
#undef alpha_ared
#undef beta_ared
#undef ared_prevtime
#undef interval
#undef link_cap
#undef lambda
#undef var_cnt_c1
#undef var_cnt_c2
#undef dvar_c1
#undef dvar_c2
#undef d_debt_c1
#undef nd_debt_c1
#undef d_debt_c2
#undef nd_debt_c2
#undef c1_stop_loss
#undef c2_stop_loss
#undef lpdf_c1_cnt
#undef lpdf_c2_cnt
#undef lpdf_limit
#undef outcome4_instance
#undef red_count
#undef routing_table
#undef bottleneck_id
#undef rtt_data

#undef FIN_PREAMBLE_DEC
#undef FIN_PREAMBLE_CODE

#define FIN_PREAMBLE_DEC
#define FIN_PREAMBLE_CODE

VosT_Obtype
_op_scheduler_TCP_rt_ttf_init (int * init_block_ptr)
	{
	VosT_Obtype obtype = OPC_NIL;
	FIN_MT (_op_scheduler_TCP_rt_ttf_init (init_block_ptr))

	obtype = Vos_Define_Object_Prstate ("proc state vars (scheduler_TCP_rt_ttf)",
		sizeof (scheduler_TCP_rt_ttf_state));
	*init_block_ptr = 0;

	FRET (obtype)
	}

VosT_Address
_op_scheduler_TCP_rt_ttf_alloc (VosT_Obtype obtype, int init_block)
	{
#if !defined (VOSD_NO_FIN)
	int _op_block_origin = 0;
#endif
	scheduler_TCP_rt_ttf_state * ptr;
	FIN_MT (_op_scheduler_TCP_rt_ttf_alloc (obtype))

	ptr = (scheduler_TCP_rt_ttf_state *)Vos_Alloc_Object (obtype);
	if (ptr != OPC_NIL)
		{
		ptr->_op_current_block = init_block;
#if defined (OPD_ALLOW_ODB)
		ptr->_op_current_state = "scheduler_TCP_rt_ttf [init enter execs]";
#endif
		}
	FRET ((VosT_Address)ptr)
	}



void
_op_scheduler_TCP_rt_ttf_svar (void * gen_ptr, const char * var_name, void ** var_p_ptr)
	{
	scheduler_TCP_rt_ttf_state		*prs_ptr;

	FIN_MT (_op_scheduler_TCP_rt_ttf_svar (gen_ptr, var_name, var_p_ptr))

	if (var_name == OPC_NIL)
		{
		*var_p_ptr = (void *)OPC_NIL;
		FOUT
		}
	prs_ptr = (scheduler_TCP_rt_ttf_state *)gen_ptr;

	if (strcmp ("fp" , var_name) == 0)
		{
		*var_p_ptr = (void *) (&prs_ptr->fp);
		FOUT
		}
	if (strcmp ("fp_loss" , var_name) == 0)
		{
		*var_p_ptr = (void *) (&prs_ptr->fp_loss);
		FOUT
		}
	if (strcmp ("fp64" , var_name) == 0)
		{
		*var_p_ptr = (void *) (&prs_ptr->fp64);
		FOUT
		}
	if (strcmp ("fp_aggr" , var_name) == 0)
		{
		*var_p_ptr = (void *) (&prs_ptr->fp_aggr);
		FOUT
		}
	if (strcmp ("debt_debug_file" , var_name) == 0)
		{
		*var_p_ptr = (void *) (&prs_ptr->debt_debug_file);
		FOUT
		}
	if (strcmp ("link_output_file" , var_name) == 0)
		{
		*var_p_ptr = (void *) (&prs_ptr->link_output_file);
		FOUT
		}
	if (strcmp ("loss_file" , var_name) == 0)
		{
		*var_p_ptr = (void *) (&prs_ptr->loss_file);
		FOUT
		}
	if (strcmp ("destroyed_file" , var_name) == 0)
		{
		*var_p_ptr = (void *) (&prs_ptr->destroyed_file);
		FOUT
		}
	if (strcmp ("destroyed0_file" , var_name) == 0)
		{
		*var_p_ptr = (void *) (&prs_ptr->destroyed0_file);
		FOUT
		}
	if (strcmp ("total_file" , var_name) == 0)
		{
		*var_p_ptr = (void *) (&prs_ptr->total_file);
		FOUT
		}
	if (strcmp ("params_file" , var_name) == 0)
		{
		*var_p_ptr = (void *) (&prs_ptr->params_file);
		FOUT
		}
	if (strcmp ("qstats_file" , var_name) == 0)
		{
		*var_p_ptr = (void *) (&prs_ptr->qstats_file);
		FOUT
		}
	if (strcmp ("loss_pdf_file" , var_name) == 0)
		{
		*var_p_ptr = (void *) (&prs_ptr->loss_pdf_file);
		FOUT
		}
	if (strcmp ("remaining_debt_file" , var_name) == 0)
		{
		*var_p_ptr = (void *) (&prs_ptr->remaining_debt_file);
		FOUT
		}
	if (strcmp ("qdata_file" , var_name) == 0)
		{
		*var_p_ptr = (void *) (&prs_ptr->qdata_file);
		FOUT
		}
	if (strcmp ("main_loss_file" , var_name) == 0)
		{
		*var_p_ptr = (void *) (&prs_ptr->main_loss_file);
		FOUT
		}
	if (strcmp ("port" , var_name) == 0)
		{
		*var_p_ptr = (void *) (&prs_ptr->port);
		FOUT
		}
	if (strcmp ("pkt" , var_name) == 0)
		{
		*var_p_ptr = (void *) (&prs_ptr->pkt);
		FOUT
		}
	if (strcmp ("subq_objid" , var_name) == 0)
		{
		*var_p_ptr = (void *) (&prs_ptr->subq_objid);
		FOUT
		}
	if (strcmp ("queue_objid" , var_name) == 0)
		{
		*var_p_ptr = (void *) (&prs_ptr->queue_objid);
		FOUT
		}
	if (strcmp ("subq_comp_attr_objid" , var_name) == 0)
		{
		*var_p_ptr = (void *) (&prs_ptr->subq_comp_attr_objid);
		FOUT
		}
	if (strcmp ("subq_size" , var_name) == 0)
		{
		*var_p_ptr = (void *) (&prs_ptr->subq_size);
		FOUT
		}
	if (strcmp ("node_id" , var_name) == 0)
		{
		*var_p_ptr = (void *) (&prs_ptr->node_id);
		FOUT
		}
	if (strcmp ("time_stamp" , var_name) == 0)
		{
		*var_p_ptr = (void *) (&prs_ptr->time_stamp);
		FOUT
		}
	if (strcmp ("tcp_pkt" , var_name) == 0)
		{
		*var_p_ptr = (void *) (&prs_ptr->tcp_pkt);
		FOUT
		}
	if (strcmp ("subq_index" , var_name) == 0)
		{
		*var_p_ptr = (void *) (&prs_ptr->subq_index);
		FOUT
		}
	if (strcmp ("test_int" , var_name) == 0)
		{
		*var_p_ptr = (void *) (&prs_ptr->test_int);
		FOUT
		}
	if (strcmp ("test_index" , var_name) == 0)
		{
		*var_p_ptr = (void *) (&prs_ptr->test_index);
		FOUT
		}
	if (strcmp ("fields_ip" , var_name) == 0)
		{
		*var_p_ptr = (void *) (&prs_ptr->fields_ip);
		FOUT
		}
	if (strcmp ("ip_address" , var_name) == 0)
		{
		*var_p_ptr = (void *) (&prs_ptr->ip_address);
		FOUT
		}
	if (strcmp ("dest_address" , var_name) == 0)
		{
		*var_p_ptr = (void *) (&prs_ptr->dest_address);
		FOUT
		}
	if (strcmp ("reserved_time" , var_name) == 0)
		{
		*var_p_ptr = (void *) (&prs_ptr->reserved_time);
		FOUT
		}
	if (strcmp ("service_time" , var_name) == 0)
		{
		*var_p_ptr = (void *) (&prs_ptr->service_time);
		FOUT
		}
	if (strcmp ("rtt1" , var_name) == 0)
		{
		*var_p_ptr = (void *) (&prs_ptr->rtt1);
		FOUT
		}
	if (strcmp ("rtt2" , var_name) == 0)
		{
		*var_p_ptr = (void *) (&prs_ptr->rtt2);
		FOUT
		}
	if (strcmp ("last_rtt" , var_name) == 0)
		{
		*var_p_ptr = (void *) (&prs_ptr->last_rtt);
		FOUT
		}
	if (strcmp ("delay_S1" , var_name) == 0)
		{
		*var_p_ptr = (void *) (&prs_ptr->delay_S1);
		FOUT
		}
	if (strcmp ("delay_S2" , var_name) == 0)
		{
		*var_p_ptr = (void *) (&prs_ptr->delay_S2);
		FOUT
		}
	if (strcmp ("delay_W1" , var_name) == 0)
		{
		*var_p_ptr = (void *) (&prs_ptr->delay_W1);
		FOUT
		}
	if (strcmp ("delay_W2" , var_name) == 0)
		{
		*var_p_ptr = (void *) (&prs_ptr->delay_W2);
		FOUT
		}
	if (strcmp ("pkt_loss1" , var_name) == 0)
		{
		*var_p_ptr = (void *) (&prs_ptr->pkt_loss1);
		FOUT
		}
	if (strcmp ("pkt_loss2" , var_name) == 0)
		{
		*var_p_ptr = (void *) (&prs_ptr->pkt_loss2);
		FOUT
		}
	if (strcmp ("pkt_total1" , var_name) == 0)
		{
		*var_p_ptr = (void *) (&prs_ptr->pkt_total1);
		FOUT
		}
	if (strcmp ("pkt_total2" , var_name) == 0)
		{
		*var_p_ptr = (void *) (&prs_ptr->pkt_total2);
		FOUT
		}
	if (strcmp ("fields_tcp" , var_name) == 0)
		{
		*var_p_ptr = (void *) (&prs_ptr->fields_tcp);
		FOUT
		}
	if (strcmp ("prev_seq1" , var_name) == 0)
		{
		*var_p_ptr = (void *) (&prs_ptr->prev_seq1);
		FOUT
		}
	if (strcmp ("prev_seq2" , var_name) == 0)
		{
		*var_p_ptr = (void *) (&prs_ptr->prev_seq2);
		FOUT
		}
	if (strcmp ("packet_format" , var_name) == 0)
		{
		*var_p_ptr = (void *) (prs_ptr->packet_format);
		FOUT
		}
	if (strcmp ("intrinsic_loss" , var_name) == 0)
		{
		*var_p_ptr = (void *) (&prs_ptr->intrinsic_loss);
		FOUT
		}
	if (strcmp ("ip_id" , var_name) == 0)
		{
		*var_p_ptr = (void *) (prs_ptr->ip_id);
		FOUT
		}
	if (strcmp ("num_formatted_fields" , var_name) == 0)
		{
		*var_p_ptr = (void *) (&prs_ptr->num_formatted_fields);
		FOUT
		}
	if (strcmp ("fmt_name" , var_name) == 0)
		{
		*var_p_ptr = (void *) (prs_ptr->fmt_name);
		FOUT
		}
	if (strcmp ("threshold" , var_name) == 0)
		{
		*var_p_ptr = (void *) (&prs_ptr->threshold);
		FOUT
		}
	if (strcmp ("red_loss" , var_name) == 0)
		{
		*var_p_ptr = (void *) (&prs_ptr->red_loss);
		FOUT
		}
	if (strcmp ("var_loss" , var_name) == 0)
		{
		*var_p_ptr = (void *) (&prs_ptr->var_loss);
		FOUT
		}
	if (strcmp ("aggr_coef" , var_name) == 0)
		{
		*var_p_ptr = (void *) (&prs_ptr->aggr_coef);
		FOUT
		}
	if (strcmp ("intr_loss_c1" , var_name) == 0)
		{
		*var_p_ptr = (void *) (&prs_ptr->intr_loss_c1);
		FOUT
		}
	if (strcmp ("intr_loss_c2" , var_name) == 0)
		{
		*var_p_ptr = (void *) (&prs_ptr->intr_loss_c2);
		FOUT
		}
	if (strcmp ("q_loss_c1" , var_name) == 0)
		{
		*var_p_ptr = (void *) (&prs_ptr->q_loss_c1);
		FOUT
		}
	if (strcmp ("q_loss_c2" , var_name) == 0)
		{
		*var_p_ptr = (void *) (&prs_ptr->q_loss_c2);
		FOUT
		}
	if (strcmp ("fq_loss_c1" , var_name) == 0)
		{
		*var_p_ptr = (void *) (&prs_ptr->fq_loss_c1);
		FOUT
		}
	if (strcmp ("fq_loss_c2" , var_name) == 0)
		{
		*var_p_ptr = (void *) (&prs_ptr->fq_loss_c2);
		FOUT
		}
	if (strcmp ("debt_loss_c1" , var_name) == 0)
		{
		*var_p_ptr = (void *) (&prs_ptr->debt_loss_c1);
		FOUT
		}
	if (strcmp ("debt_loss_c2" , var_name) == 0)
		{
		*var_p_ptr = (void *) (&prs_ptr->debt_loss_c2);
		FOUT
		}
	if (strcmp ("queue_id" , var_name) == 0)
		{
		*var_p_ptr = (void *) (&prs_ptr->queue_id);
		FOUT
		}
	if (strcmp ("app_id" , var_name) == 0)
		{
		*var_p_ptr = (void *) (&prs_ptr->app_id);
		FOUT
		}
	if (strcmp ("app_defs_objid" , var_name) == 0)
		{
		*var_p_ptr = (void *) (&prs_ptr->app_defs_objid);
		FOUT
		}
	if (strcmp ("dest_pref_objid" , var_name) == 0)
		{
		*var_p_ptr = (void *) (&prs_ptr->dest_pref_objid);
		FOUT
		}
	if (strcmp ("dest_pref_value" , var_name) == 0)
		{
		*var_p_ptr = (void *) (&prs_ptr->dest_pref_value);
		FOUT
		}
	if (strcmp ("cnt_total_in" , var_name) == 0)
		{
		*var_p_ptr = (void *) (&prs_ptr->cnt_total_in);
		FOUT
		}
	if (strcmp ("cnt_total_out" , var_name) == 0)
		{
		*var_p_ptr = (void *) (&prs_ptr->cnt_total_out);
		FOUT
		}
	if (strcmp ("cnt_total_destroyed" , var_name) == 0)
		{
		*var_p_ptr = (void *) (&prs_ptr->cnt_total_destroyed);
		FOUT
		}
	if (strcmp ("dest_addr" , var_name) == 0)
		{
		*var_p_ptr = (void *) (&prs_ptr->dest_addr);
		FOUT
		}
	if (strcmp ("fact_conv" , var_name) == 0)
		{
		*var_p_ptr = (void *) (&prs_ptr->fact_conv);
		FOUT
		}
	if (strcmp ("extract_pkt" , var_name) == 0)
		{
		*var_p_ptr = (void *) (&prs_ptr->extract_pkt);
		FOUT
		}
	if (strcmp ("flag_ttf" , var_name) == 0)
		{
		*var_p_ptr = (void *) (&prs_ptr->flag_ttf);
		FOUT
		}
	if (strcmp ("drop_debt" , var_name) == 0)
		{
		*var_p_ptr = (void *) (&prs_ptr->drop_debt);
		FOUT
		}
	if (strcmp ("drop_debt0" , var_name) == 0)
		{
		*var_p_ptr = (void *) (&prs_ptr->drop_debt0);
		FOUT
		}
	if (strcmp ("drop_debt1" , var_name) == 0)
		{
		*var_p_ptr = (void *) (&prs_ptr->drop_debt1);
		FOUT
		}
	if (strcmp ("drop_debt2" , var_name) == 0)
		{
		*var_p_ptr = (void *) (&prs_ptr->drop_debt2);
		FOUT
		}
	if (strcmp ("drop_debt3" , var_name) == 0)
		{
		*var_p_ptr = (void *) (&prs_ptr->drop_debt3);
		FOUT
		}
	if (strcmp ("cur_seq" , var_name) == 0)
		{
		*var_p_ptr = (void *) (&prs_ptr->cur_seq);
		FOUT
		}
	if (strcmp ("last_ok" , var_name) == 0)
		{
		*var_p_ptr = (void *) (&prs_ptr->last_ok);
		FOUT
		}
	if (strcmp ("last_ok0" , var_name) == 0)
		{
		*var_p_ptr = (void *) (&prs_ptr->last_ok0);
		FOUT
		}
	if (strcmp ("last_ok1" , var_name) == 0)
		{
		*var_p_ptr = (void *) (&prs_ptr->last_ok1);
		FOUT
		}
	if (strcmp ("last_ok2" , var_name) == 0)
		{
		*var_p_ptr = (void *) (&prs_ptr->last_ok2);
		FOUT
		}
	if (strcmp ("last_ok3" , var_name) == 0)
		{
		*var_p_ptr = (void *) (&prs_ptr->last_ok3);
		FOUT
		}
	if (strcmp ("drop_reg3" , var_name) == 0)
		{
		*var_p_ptr = (void *) (prs_ptr->drop_reg3);
		FOUT
		}
	if (strcmp ("drop_reg2" , var_name) == 0)
		{
		*var_p_ptr = (void *) (prs_ptr->drop_reg2);
		FOUT
		}
	if (strcmp ("drop_reg1" , var_name) == 0)
		{
		*var_p_ptr = (void *) (prs_ptr->drop_reg1);
		FOUT
		}
	if (strcmp ("drop_reg0" , var_name) == 0)
		{
		*var_p_ptr = (void *) (prs_ptr->drop_reg0);
		FOUT
		}
	if (strcmp ("drop_reg" , var_name) == 0)
		{
		*var_p_ptr = (void *) (prs_ptr->drop_reg);
		FOUT
		}
	if (strcmp ("L" , var_name) == 0)
		{
		*var_p_ptr = (void *) (&prs_ptr->L);
		FOUT
		}
	if (strcmp ("i" , var_name) == 0)
		{
		*var_p_ptr = (void *) (&prs_ptr->i);
		FOUT
		}
	if (strcmp ("droppable" , var_name) == 0)
		{
		*var_p_ptr = (void *) (&prs_ptr->droppable);
		FOUT
		}
	if (strcmp ("nxt_idx" , var_name) == 0)
		{
		*var_p_ptr = (void *) (&prs_ptr->nxt_idx);
		FOUT
		}
	if (strcmp ("nxt_idx0" , var_name) == 0)
		{
		*var_p_ptr = (void *) (&prs_ptr->nxt_idx0);
		FOUT
		}
	if (strcmp ("nxt_idx1" , var_name) == 0)
		{
		*var_p_ptr = (void *) (&prs_ptr->nxt_idx1);
		FOUT
		}
	if (strcmp ("nxt_idx2" , var_name) == 0)
		{
		*var_p_ptr = (void *) (&prs_ptr->nxt_idx2);
		FOUT
		}
	if (strcmp ("nxt_idx3" , var_name) == 0)
		{
		*var_p_ptr = (void *) (&prs_ptr->nxt_idx3);
		FOUT
		}
	if (strcmp ("repetition" , var_name) == 0)
		{
		*var_p_ptr = (void *) (&prs_ptr->repetition);
		FOUT
		}
	if (strcmp ("outcome" , var_name) == 0)
		{
		*var_p_ptr = (void *) (&prs_ptr->outcome);
		FOUT
		}
	if (strcmp ("increase_debt" , var_name) == 0)
		{
		*var_p_ptr = (void *) (&prs_ptr->increase_debt);
		FOUT
		}
	if (strcmp ("contador_test" , var_name) == 0)
		{
		*var_p_ptr = (void *) (&prs_ptr->contador_test);
		FOUT
		}
	if (strcmp ("might_drop" , var_name) == 0)
		{
		*var_p_ptr = (void *) (&prs_ptr->might_drop);
		FOUT
		}
	if (strcmp ("last_lost" , var_name) == 0)
		{
		*var_p_ptr = (void *) (&prs_ptr->last_lost);
		FOUT
		}
	if (strcmp ("last_lost0" , var_name) == 0)
		{
		*var_p_ptr = (void *) (&prs_ptr->last_lost0);
		FOUT
		}
	if (strcmp ("last_lost1" , var_name) == 0)
		{
		*var_p_ptr = (void *) (&prs_ptr->last_lost1);
		FOUT
		}
	if (strcmp ("last_lost2" , var_name) == 0)
		{
		*var_p_ptr = (void *) (&prs_ptr->last_lost2);
		FOUT
		}
	if (strcmp ("last_lost3" , var_name) == 0)
		{
		*var_p_ptr = (void *) (&prs_ptr->last_lost3);
		FOUT
		}
	if (strcmp ("l11_id" , var_name) == 0)
		{
		*var_p_ptr = (void *) (&prs_ptr->l11_id);
		FOUT
		}
	if (strcmp ("l12_id" , var_name) == 0)
		{
		*var_p_ptr = (void *) (&prs_ptr->l12_id);
		FOUT
		}
	if (strcmp ("l21_id" , var_name) == 0)
		{
		*var_p_ptr = (void *) (&prs_ptr->l21_id);
		FOUT
		}
	if (strcmp ("l22_id" , var_name) == 0)
		{
		*var_p_ptr = (void *) (&prs_ptr->l22_id);
		FOUT
		}
	if (strcmp ("d11" , var_name) == 0)
		{
		*var_p_ptr = (void *) (&prs_ptr->d11);
		FOUT
		}
	if (strcmp ("d12" , var_name) == 0)
		{
		*var_p_ptr = (void *) (&prs_ptr->d12);
		FOUT
		}
	if (strcmp ("d21" , var_name) == 0)
		{
		*var_p_ptr = (void *) (&prs_ptr->d21);
		FOUT
		}
	if (strcmp ("d22" , var_name) == 0)
		{
		*var_p_ptr = (void *) (&prs_ptr->d22);
		FOUT
		}
	if (strcmp ("rtt_c1" , var_name) == 0)
		{
		*var_p_ptr = (void *) (&prs_ptr->rtt_c1);
		FOUT
		}
	if (strcmp ("rtt_c2" , var_name) == 0)
		{
		*var_p_ptr = (void *) (&prs_ptr->rtt_c2);
		FOUT
		}
	if (strcmp ("alg_num" , var_name) == 0)
		{
		*var_p_ptr = (void *) (&prs_ptr->alg_num);
		FOUT
		}
	if (strcmp ("pkts_inq" , var_name) == 0)
		{
		*var_p_ptr = (void *) (&prs_ptr->pkts_inq);
		FOUT
		}
	if (strcmp ("q_delay" , var_name) == 0)
		{
		*var_p_ptr = (void *) (&prs_ptr->q_delay);
		FOUT
		}
	if (strcmp ("cur_qsize" , var_name) == 0)
		{
		*var_p_ptr = (void *) (&prs_ptr->cur_qsize);
		FOUT
		}
	if (strcmp ("qsize_sample" , var_name) == 0)
		{
		*var_p_ptr = (void *) (&prs_ptr->qsize_sample);
		FOUT
		}
	if (strcmp ("smoothing" , var_name) == 0)
		{
		*var_p_ptr = (void *) (&prs_ptr->smoothing);
		FOUT
		}
	if (strcmp ("w_q" , var_name) == 0)
		{
		*var_p_ptr = (void *) (&prs_ptr->w_q);
		FOUT
		}
	if (strcmp ("s_red" , var_name) == 0)
		{
		*var_p_ptr = (void *) (&prs_ptr->s_red);
		FOUT
		}
	if (strcmp ("idle_stamp" , var_name) == 0)
		{
		*var_p_ptr = (void *) (&prs_ptr->idle_stamp);
		FOUT
		}
	if (strcmp ("idle_power" , var_name) == 0)
		{
		*var_p_ptr = (void *) (&prs_ptr->idle_power);
		FOUT
		}
	if (strcmp ("last_q_record" , var_name) == 0)
		{
		*var_p_ptr = (void *) (&prs_ptr->last_q_record);
		FOUT
		}
	if (strcmp ("dt_q" , var_name) == 0)
		{
		*var_p_ptr = (void *) (&prs_ptr->dt_q);
		FOUT
		}
	if (strcmp ("my_id" , var_name) == 0)
		{
		*var_p_ptr = (void *) (&prs_ptr->my_id);
		FOUT
		}
	if (strcmp ("bg_dist" , var_name) == 0)
		{
		*var_p_ptr = (void *) (prs_ptr->bg_dist);
		FOUT
		}
	if (strcmp ("bg_iat" , var_name) == 0)
		{
		*var_p_ptr = (void *) (&prs_ptr->bg_iat);
		FOUT
		}
	if (strcmp ("recommended_red" , var_name) == 0)
		{
		*var_p_ptr = (void *) (&prs_ptr->recommended_red);
		FOUT
		}
	if (strcmp ("gentle_flag" , var_name) == 0)
		{
		*var_p_ptr = (void *) (&prs_ptr->gentle_flag);
		FOUT
		}
	if (strcmp ("min_th" , var_name) == 0)
		{
		*var_p_ptr = (void *) (&prs_ptr->min_th);
		FOUT
		}
	if (strcmp ("max_p" , var_name) == 0)
		{
		*var_p_ptr = (void *) (&prs_ptr->max_p);
		FOUT
		}
	if (strcmp ("fbase_str" , var_name) == 0)
		{
		*var_p_ptr = (void *) (prs_ptr->fbase_str);
		FOUT
		}
	if (strcmp ("files_str" , var_name) == 0)
		{
		*var_p_ptr = (void *) (prs_ptr->files_str);
		FOUT
		}
	if (strcmp ("alpha_feng" , var_name) == 0)
		{
		*var_p_ptr = (void *) (&prs_ptr->alpha_feng);
		FOUT
		}
	if (strcmp ("beta_feng" , var_name) == 0)
		{
		*var_p_ptr = (void *) (&prs_ptr->beta_feng);
		FOUT
		}
	if (strcmp ("feng" , var_name) == 0)
		{
		*var_p_ptr = (void *) (&prs_ptr->feng);
		FOUT
		}
	if (strcmp ("feng_status" , var_name) == 0)
		{
		*var_p_ptr = (void *) (&prs_ptr->feng_status);
		FOUT
		}
	if (strcmp ("max_th" , var_name) == 0)
		{
		*var_p_ptr = (void *) (&prs_ptr->max_th);
		FOUT
		}
	if (strcmp ("target_delay" , var_name) == 0)
		{
		*var_p_ptr = (void *) (&prs_ptr->target_delay);
		FOUT
		}
	if (strcmp ("sally" , var_name) == 0)
		{
		*var_p_ptr = (void *) (&prs_ptr->sally);
		FOUT
		}
	if (strcmp ("alpha_ared" , var_name) == 0)
		{
		*var_p_ptr = (void *) (&prs_ptr->alpha_ared);
		FOUT
		}
	if (strcmp ("beta_ared" , var_name) == 0)
		{
		*var_p_ptr = (void *) (&prs_ptr->beta_ared);
		FOUT
		}
	if (strcmp ("ared_prevtime" , var_name) == 0)
		{
		*var_p_ptr = (void *) (&prs_ptr->ared_prevtime);
		FOUT
		}
	if (strcmp ("interval" , var_name) == 0)
		{
		*var_p_ptr = (void *) (&prs_ptr->interval);
		FOUT
		}
	if (strcmp ("link_cap" , var_name) == 0)
		{
		*var_p_ptr = (void *) (&prs_ptr->link_cap);
		FOUT
		}
	if (strcmp ("lambda" , var_name) == 0)
		{
		*var_p_ptr = (void *) (&prs_ptr->lambda);
		FOUT
		}
	if (strcmp ("var_cnt_c1" , var_name) == 0)
		{
		*var_p_ptr = (void *) (&prs_ptr->var_cnt_c1);
		FOUT
		}
	if (strcmp ("var_cnt_c2" , var_name) == 0)
		{
		*var_p_ptr = (void *) (&prs_ptr->var_cnt_c2);
		FOUT
		}
	if (strcmp ("dvar_c1" , var_name) == 0)
		{
		*var_p_ptr = (void *) (&prs_ptr->dvar_c1);
		FOUT
		}
	if (strcmp ("dvar_c2" , var_name) == 0)
		{
		*var_p_ptr = (void *) (&prs_ptr->dvar_c2);
		FOUT
		}
	if (strcmp ("d_debt_c1" , var_name) == 0)
		{
		*var_p_ptr = (void *) (&prs_ptr->d_debt_c1);
		FOUT
		}
	if (strcmp ("nd_debt_c1" , var_name) == 0)
		{
		*var_p_ptr = (void *) (&prs_ptr->nd_debt_c1);
		FOUT
		}
	if (strcmp ("d_debt_c2" , var_name) == 0)
		{
		*var_p_ptr = (void *) (&prs_ptr->d_debt_c2);
		FOUT
		}
	if (strcmp ("nd_debt_c2" , var_name) == 0)
		{
		*var_p_ptr = (void *) (&prs_ptr->nd_debt_c2);
		FOUT
		}
	if (strcmp ("c1_stop_loss" , var_name) == 0)
		{
		*var_p_ptr = (void *) (&prs_ptr->c1_stop_loss);
		FOUT
		}
	if (strcmp ("c2_stop_loss" , var_name) == 0)
		{
		*var_p_ptr = (void *) (&prs_ptr->c2_stop_loss);
		FOUT
		}
	if (strcmp ("lpdf_c1_cnt" , var_name) == 0)
		{
		*var_p_ptr = (void *) (&prs_ptr->lpdf_c1_cnt);
		FOUT
		}
	if (strcmp ("lpdf_c2_cnt" , var_name) == 0)
		{
		*var_p_ptr = (void *) (&prs_ptr->lpdf_c2_cnt);
		FOUT
		}
	if (strcmp ("lpdf_limit" , var_name) == 0)
		{
		*var_p_ptr = (void *) (&prs_ptr->lpdf_limit);
		FOUT
		}
	if (strcmp ("outcome4_instance" , var_name) == 0)
		{
		*var_p_ptr = (void *) (&prs_ptr->outcome4_instance);
		FOUT
		}
	if (strcmp ("red_count" , var_name) == 0)
		{
		*var_p_ptr = (void *) (&prs_ptr->red_count);
		FOUT
		}
	if (strcmp ("routing_table" , var_name) == 0)
		{
		*var_p_ptr = (void *) (prs_ptr->routing_table);
		FOUT
		}
	if (strcmp ("bottleneck_id" , var_name) == 0)
		{
		*var_p_ptr = (void *) (&prs_ptr->bottleneck_id);
		FOUT
		}
	if (strcmp ("rtt_data" , var_name) == 0)
		{
		*var_p_ptr = (void *) (&prs_ptr->rtt_data);
		FOUT
		}
	*var_p_ptr = (void *)OPC_NIL;

	FOUT
	}

