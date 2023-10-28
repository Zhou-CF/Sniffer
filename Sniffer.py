import sys

from PyQt5.QtCore import QThread, pyqtSignal, QSize
from PyQt5.QtGui import QIcon
from PyQt5.QtWidgets import QMainWindow, QApplication, QRadioButton, QVBoxLayout, QWidget, QTableWidgetItem
from functools import partial
from scapy.all import *

from UI import UI
import images_rc


class Sniffer(QThread):
    data_signal = pyqtSignal(list)
    hex_signal = pyqtSignal(list)

    def __init__(self, iface, filter):
        super().__init__()
        self.iface = iface
        self.filter = filter
        self.hex_list = []
        self.details = []

    def deal_summary(self, summary_text):
        data = summary_text.split(' / ')
        network = data[2].split(' ')[0]
        return network

    def deal_ARP(self, packet):
        info = packet.summary()
        protocol = packet[1].name
        src_ip = packet[1].psrc
        dst_ip = packet[1].pdst
        length = len(packet)
        self.hex_list.append(hexdump(packet, dump=True))
        self.details.append(packet.show(dump=True))
        self.data_signal.emit([src_ip, dst_ip, protocol, str(length), info])

    def deal_IP(self, packet):
        info = packet.summary()
        protocol = self.deal_summary(info)
        src_ip = packet[1].src
        dst_ip = packet[1].dst
        length = len(packet)
        self.hex_list.append(hexdump(packet, dump=True))
        self.details.append(packet.show(dump=True))
        self.data_signal.emit([src_ip, dst_ip, protocol, str(length), info])

    def run(self):
        def prn(packet):
            if packet[1].name == 'ARP':
                self.deal_ARP(packet)
            if packet[1].name != 'ARP':
                print(packet[1].name)
                self.deal_IP(packet)
            else:
                print(packet[1].name)
        try:
            sniff(iface=self.iface, prn=prn, filter=self.filter)
        except:
            sys.exit()

    def get_hex(self, index: int):
        print(index)
        content = [self.hex_list[index], self.details[index]]
        # text = self.hex_list[index]
        # print(type(text))
        print(content[0])
        print(content[1])
        self.hex_signal.emit(content)

    def stop(self):
        self.terminate()


class show_window(UI.Ui_MainWindow, QMainWindow):
    def __init__(self):
        super(show_window, self).__init__()
        self.setupUi(self)

        self.THREAD = {}

        self.net_list = get_working_ifaces()
        self.initUI()
        # 控制表格滚动条
        self.vertical_Scrolling = True

    def initUI(self):
        # 设置开始和暂停图标
        self.start_btn.setIcon(QIcon(':/start.png'))
        self.start_btn.setIconSize(QSize(40, 40))
        self.stop_btn.setIcon(QIcon(':/stop.png'))
        self.stop_btn.setIconSize(QSize(40, 40))

        # 控制现实页面
        self.stackedWidget.setCurrentIndex(0)
        self.pushButton.clicked.connect(partial(self.display_page, 0))
        self.pushButton_2.clicked.connect(partial(self.display_page, 1))

        # 建立网卡选项
        vbox = QVBoxLayout()
        self.scrollWidget = QWidget()
        self.scrollLayout = QVBoxLayout(self.scrollWidget)

        # 储存网卡
        self.buttons = []

        for i in range(len(self.net_list)):
            radio_button = QRadioButton(
                self.net_list[i].name + '    IP:' + (self.net_list[i].ip if self.net_list[i].ip else '无地址'))
            self.scrollLayout.addWidget(radio_button)
            self.buttons.append(radio_button)

        self.scrollArea.setWidget(self.scrollWidget)
        vbox.addWidget(self.scrollArea)

        self.setLayout(vbox)

        # 设置网卡选择按钮
        self.select_net_Button.clicked.connect(self.getSelectedValue)
        self.stop_btn.clicked.connect(self.stop_net)
        self.stop_btn.setEnabled(False)
        self.start_btn.clicked.connect(self.start_net)

        # 确定过滤语句
        self.pushButton_3.clicked.connect(self.get_filter)

        # 绑定表格点击
        self.tableWidget.itemClicked.connect(self.get_hex)

    def get_filter(self):
        filter_text = self.lineEdit.text()
        self.getSelectedValue(filter_text)

    # 获取filter
    def get_lineText(self):
        text = self.lineEdit.text()
        return text

    # 获取网卡选择
    def getSelectedValue(self, filter_text=''):
        if self.THREAD.get(0):
            self.THREAD[0].stop()
        network = ''
        for i, button in enumerate(self.buttons):
            if button.isChecked():
                network = self.net_list[i]
        if network:
            self.update_net(network, filter_text)

    # 设置展示页面
    def display_page(self, index: int):
        self.stackedWidget.setCurrentIndex(index)

    # 清空表格内容
    def clearTable(self):
        self.tableWidget.setRowCount(0)
        self.textEdit.clear()
        self.textEdit_2.clear()
        self.lineEdit_2.clear()

    # 更新数据
    def update_net(self, iface, filter=''):
        # 清空表格
        self.clearTable()
        # 建立嗅探进程
        self.THREAD[0] = Sniffer(iface, filter)
        self.THREAD[0].data_signal.connect(self.display_data)
        self.THREAD[0].hex_signal.connect(self.display_hex)
        self.THREAD[0].start()

        # 跳至嗅探显示界面
        self.display_page(1)
        self.pushButton.setEnabled(False)
        self.start_btn.setEnabled(False)
        self.stop_btn.setEnabled(True)

    # 展示数据
    def display_data(self, data):
        col_num = len(data)
        rowPosition = self.tableWidget.rowCount()  # 获取当前行数
        self.tableWidget.insertRow(rowPosition)  # 在最后插入新行
        # 添加单元格内容
        for i in range(col_num):
            self.tableWidget.setItem(rowPosition, i, QTableWidgetItem(data[i]))
        self.check_scroll(rowPosition)

    # 获取索引传给线程
    def get_hex(self, item):
        index = item.row()
        info_text = self.tableWidget.item(index, 4)
        self.lineEdit_2.setText(info_text.text())
        self.THREAD[0].get_hex(index)

    # 显示其中某条信息
    def display_hex(self, hex_text):
        print(hex_text)
        self.textEdit.setText(hex_text[0])
        self.textEdit_2.setText(hex_text[1])

        # print(hex_text)

    # 检测滚动条状态
    def check_scroll(self, rowPosition):
        if self.vertical_Scrolling:
            self.tableWidget.scrollToBottom()
        self.tableWidget.verticalScrollBar().sliderPressed.connect(self.set_unRoll)
        scroll_pos = self.tableWidget.verticalScrollBar().sliderPosition()
        if self.tableWidget.verticalScrollBar().sliderReleased and rowPosition - scroll_pos < 10:
            self.vertical_Scrolling = True

    def set_unRoll(self):
        self.vertical_Scrolling = False

    # 开始 停止/终止
    def stop_net(self):
        self.THREAD[0].stop()

        self.pushButton.setEnabled(True)
        self.stop_btn.setEnabled(False)
        self.start_btn.setEnabled(True)

    def start_net(self):
        self.getSelectedValue()


if __name__ == '__main__':
    app = QApplication(sys.argv)
    myshow = show_window()
    myshow.show()
    app.exec()
