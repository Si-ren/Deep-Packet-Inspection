#include "dpi_list.h"
#include <stdlib.h>
//初始化
//    创建一个链表
//    出错返回NULL
dpi_list *dpi_list_create()
{
    dpi_list *list = calloc(1,sizeof(dpi_list));
    if(list)
    {
        //刚开始只有一个哨兵节点的情况下，next 和 prev都指向自身
        list->sentinel.next=&list->sentinel;
        list->sentinel.prev=&list->sentinel;
    }
    return list;
}

//业务处理
//    往链表中追加新的数据元素
//    成功返回链表大小，失败返回-1
int dpi_list_append(dpi_list *list, void *data)
{
    //创建新节点
    dpi_list_node *newNode = malloc(sizeof(dpi_list_node));
    if(newNode==NULL)
    {
        return -1;
    }
    newNode->data = data;
    //节点中的指针的赋值
    //当前链表中的最后一个节点为lastNode，可以从哨兵节点的prev获取
    dpi_list_node *lastNode = list->sentinel.prev;
    //1 newNode的prev指向lastNode
    newNode->prev = lastNode;
    //2 lastNode的next指向newNode
    lastNode->next = newNode;
    //3 newNode的next要指向sentinel
    newNode->next=&list->sentinel;
    //4 sentinel的prev要指向newNode
    list->sentinel.prev=newNode;

    //list的带下要增加
    list->size++;
    return 0;
}


//垃圾回收
//销毁链表
void dpi_list_destroy(dpi_list *list,void (*data_destroy_func)(void *data))
{
    if(list==NULL)
        return;
    
    //遍历，销毁每一节点
    dpi_list_node *node = list->sentinel.next;
    while(node!=&list->sentinel)
    {
        dpi_list_node *tmp = node;
        node = node->next;

        if(tmp->data&&data_destroy_func)
        {
            //帮调用释放函数来释放data节点
            data_destroy_func(tmp->data);
        }
        free(tmp);
    }
    //销毁list
    free(list);
}
