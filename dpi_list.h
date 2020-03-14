
typedef struct dpi_list_node
{
    void *data;         //data区域通用化
    struct dpi_list_node *prev;     //指向前一个节点的指针
    struct dpi_list_node *next;     //指向后一个节点的指针
}dpi_list_node;


typedef struct dpi_list
{
    unsigned int size;          //链表节点的数量
    dpi_list_node sentinel;         //链表的哨兵节点
}dpi_list;
//初始化
//    创建一个链表
//    出错返回NULL
dpi_list *dpi_list_create();

//业务处理
//    往链表中追加新的数据元素
//    成功返回链表大小，失败返回-1
int dpi_list_append(dpi_list *list, void *data);


//垃圾回收
//销毁链表
//data_destroy_func是用于销毁data域的一个函数
void dpi_list_destroy(dpi_list *list,void (*data_destroy_func)(void *data));
