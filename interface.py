import pandas as pd

from PySide6.QtWidgets import QTableView, QApplication, QToolBar, QMainWindow, QLineEdit, QWidget, QGridLayout, QPushButton, QLabel, QComboBox
from PySide6.QtGui import QAction
from PySide6.QtCore import QAbstractTableModel, Qt, QModelIndex
import sys


class PandasModel(QAbstractTableModel):
    """A model to interface a Qt view with pandas dataframe """

    def __init__(self, DataBase, parent=None):
        QAbstractTableModel.__init__(self, parent)
        self.DataBase = DataBase
        self.type = 0

    def rowCount(self, parent=QModelIndex()) -> int:
        if parent == QModelIndex():
            return len(self.DataBase[self.type])

        return 0

    def columnCount(self, parent=QModelIndex()) -> int:
        if parent == QModelIndex():
            return len(self.DataBase[self.type].columns)
        return 0

    def data(self, index: QModelIndex, role=Qt.ItemDataRole):
        if not index.isValid():
            return None

        if role == Qt.ItemDataRole.DisplayRole:
            return str(self.DataBase[self.type].iloc[index.row(), index.column()])

        return None

    def headerData(
        self, section: int, orientation: Qt.Orientation, role: Qt.ItemDataRole
    ):
        if role == Qt.ItemDataRole.DisplayRole:
            if orientation == Qt.Orientation.Horizontal:
                return str(self.DataBase[self.type].columns[section])

            if orientation == Qt.Vertical:
                return str(self.DataBase[self.type].index[section])

        return None

    def setData(self, index, value, role):
        if role == Qt.EditRole:
            self._data.iloc[index.row(),index.column()] = value
            return True
    def flags(self, index):
        return Qt.ItemIsSelectable | Qt.ItemIsEnabled | Qt.ItemIsEditable

    def update(self):
        self.beginResetModel()
        #self.DataBase[self.type] = self.DataBase[self.type]
        self.endResetModel()

class DFWidget(QTableView):
    def __init__(self, df):
        super().__init__()
        super().horizontalHeader().setStretchLastSection(True)
        super().setAlternatingRowColors(True)
        super().setSelectionBehavior(QTableView.SelectRows)
        self.model = PandasModel(df)
        super().setModel(self.model)
    def update(self):
        self.model.update()
    def change_type(self, type):
        self.model.type = type
    


class Input_Button(QWidget):
    def __init__(self, parent=None, funk = None, Name = '', Text = ''):
        super().__init__(parent)

        self.imput_line = QLineEdit(parent=self)
        self.imput_line.setPlaceholderText(Text)
        submit_button = QPushButton(parent=self, text=Name)
        submit_button.clicked.connect(funk)
        layout = QGridLayout()
        layout.addWidget(self.imput_line, 0, 0)
        layout.addWidget(submit_button, 0, 1)
        self.setLayout(layout)


class Display(QWidget):
    def __init__(self, parent = None, df = None):
        super().__init__(parent)
        self.data = df
        self.type = 0
        self.DF = DFWidget(df)
        self.display = QLabel(parent = self)
        self.DF.clicked.connect(self.set_text)
        layout = QGridLayout()
        layout.addWidget(self.DF, 0, 0)
        layout.addWidget(self.display, 0, 1)
        self.setLayout(layout)

    def set_text(self):
        index = self.DF.selectedIndexes()[0].row()
        self.display.setText(str(self.data[self.type].loc[index]))

    def update(self):
        self.DF.update()

    def change_type(self, type):
        self.DF.change_type(type)
        self.type = type



class Main_window(QMainWindow):
    def __init__(self, df):
        super().__init__()
        self.centralWidget = Display(self, df)
        self.setCentralWidget(self.centralWidget)
        self._createToolBars()

    def _createActions(self):
        self.refreshAction = QAction("Refresh", self)
        self.refreshAction.triggered.connect(self.refreshed)
        self.sort_by_src_mac = Input_Button(self, self.sort_src_mac, 'Sort', 'Sort source mac')
        self.sort_by_src_mac.setFocusPolicy(Qt.NoFocus)
        self.sort_by_dst_mac = Input_Button(self, self.sort_dst_mac, 'Sort', 'Sort destination mac')
        self.sort_by_dst_mac.setFocusPolicy(Qt.NoFocus)
        self.sort_by_src_ip = Input_Button(self, self.sort_src_ip, 'Sort', 'Sort source ip')
        self.sort_by_src_ip.setFocusPolicy(Qt.NoFocus)
        self.sort_by_dst_ip = Input_Button(self, self.sort_dst_ip, 'Sort', 'Sort destination ip')
        self.sort_by_dst_ip.setFocusPolicy(Qt.NoFocus)
        self.type = QComboBox()
        self.type.addItem('One')
        self.type.addItem('Two')
        self.type.setFocusPolicy(Qt.NoFocus)
        self.type.currentIndexChanged.connect(self.type_changed)


    def type_changed(self, index):
        self.centralWidget.change_type(index)
        self.centralWidget.update()
    def refreshed(self):
        self.centralWidget.update()
    def sort_src_mac(self):
        print('sorted src mac by:', self.sort_by_src_mac.imput_line.displayText())
    def sort_dst_mac(self):
        print('sorted dst mac by:', self.sort_by_dst_mac.imput_line.displayText())
    def sort_src_ip(self):
        print('sorted src ip by:', self.sort_by_src_ip.imput_line.displayText())
    def sort_dst_ip(self):
        print('sorted dst ip by:', self.sort_by_dst_ip.imput_line.displayText())


    def _createToolBars(self):
        self._createActions()
        ActionlBar = self.addToolBar("Actions")
        ActionlBar.addAction(self.refreshAction)
        ActionlBar.addWidget(self.type)
        # Edit toolbar
        SortingToolBar = self.addToolBar("Sorting")
        SortingToolBar.addWidget(self.sort_by_src_mac)
        SortingToolBar.addWidget(self.sort_by_dst_mac)
        SortingToolBar.addWidget(self.sort_by_src_ip)
        SortingToolBar.addWidget(self.sort_by_dst_ip)



if __name__ == "__main__":

    app = QApplication([])

    df1 = pd.read_csv("iris.csv")
    df2 = pd.DataFrame({'a' : [0]})

    view = Main_window([df1, df2])
    view.show()
    app.exec()


