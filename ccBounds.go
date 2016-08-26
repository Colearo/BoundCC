package main

import (
	"errors"
	"fmt"
	"strconv"

	"github.com/hyperledger/fabric/core/chaincode/shim"
	"github.com/hyperledger/fabric/core/crypto/primitives"
	"github.com/op/go-logging"
)

//终端输出显示
var mylog = logging.MustGetLogger("bounds_mgm")

//预定义所有
//字段
const (
	tableTitle     = "BoundsMgm"
	titleAccountID = "AccountID"
	titleBounds    = "Bounds"
)

type BoundsChaincode struct {
}

// 存储所有user的列表
var usrIndexStr = "_usrindex"

// Init 在 Deploy 时被调用
// 此时需要将 Deploy 的 metadata 包含 管理员证书
func (t *BoundsChaincode) Init(stub *shim.ChaincodeStub, function string, args []string) ([]byte, error) {
	mylog.Debug("***************Init*****************")

	mylog.Debug("Init Chaincode...")
	if len(args) != 0 {
		return nil, errors.New("Incorrect number of arguments. Expecting 1")
	}

	// 创建BoundsMgm表
	// 包含字段
	// "0"						"1"
	// "AccountID"		"Bounds"
	err := stub.CreateTable(tableTitle, []*shim.ColumnDefinition{
		&shim.ColumnDefinition{Name: titleAccountID, Type: shim.ColumnDefinition_STRING, Key: true},
		&shim.ColumnDefinition{Name: titleBounds, Type: shim.ColumnDefinition_INT64, Key: false},
	})
	if err != nil {
		return nil, errors.New("Failed to create table.")
	}

	// 获得的Metadata即元数据这里是
	// 合约的部署者的EnrollmentCert
	// adminCert, err := stub.GetCallerMetadata()
	// if err != nil {
	// 	mylog.Debug("Failed to get metadata")
	// 	return nil, errors.New("Failed getting metadata.")
	// }
	// if len(adminCert) == 0 {
	// 	mylog.Debug("Invalid admin certificate. Empty.")
	// 	return nil, errors.New("Invalid admin certificate. Empty.")
	// }
	//
	// mylog.Debug("The administrator is [%s]", adminCert)
	//
	// stub.PutState("admin", adminCert)

	var bounds int64
	bounds = 10000000
	ok, err := stub.InsertRow(tableTitle, shim.Row{
		Columns: []*shim.Column{
			&shim.Column{Value: &shim.Column_String_{String_: "admin"}},
			&shim.Column{Value: &shim.Column_Int64{Int64: bounds}}},
	})

	if !ok && err == nil {
		return nil, errors.New("Account was already assigned.")
	}

	mylog.Debug("Init Chaincode...Done!")

	return nil, nil
}

// Invoke 包含以下功能
// **AssignAccount
// **TransferBounds
func (t *BoundsChaincode) Invoke(stub *shim.ChaincodeStub, function string, args []string) ([]byte, error) {
	mylog.Debug("***************Invoke****************")
	// 进入以下不同函数
	if function == "assign" {
		// Assign Account
		return t.assign(stub, args)
	} else if function == "transfer" {
		// Transfer Bounds
		return t.transfer(stub, args)
	}

	return nil, errors.New("Received unknown function invocation")
}

func (t *BoundsChaincode) Query(stub *shim.ChaincodeStub, function string, args []string) ([]byte, error) {
	mylog.Debug("******************Query******************")

	// 处理不同函数
	if function == "getBalance" {
		return t.getBalance(stub, args)
	} else if function == "read" {
		return t.read(stub, args)
	}

	return nil, errors.New("Received unknown function query invocation with function " + function)
}

func (t *BoundsChaincode) read(stub *shim.ChaincodeStub, args []string) ([]byte, error) {

	if len(args) < 1 {
		return nil, errors.New("get operation must include one argument, a key")
	}
	key := args[0]
	value, err := stub.GetState(key)

	if err != nil {
		return nil, fmt.Errorf("get operation failed. Error accessing state: %s", err)
	}
	return value, nil
}

// 该ACL(Access Control Layer)使用fabric的一种认证方式，使用非永久的
// Tcert，该证书有过期和重新生成，比持久性的Ecert更能保密确认交易，caller
// 调用者传入在Json数据中的Metadata（元数据）是 Sigma
// 下面需要Verify \Sigma
// Sigma ＝ Sign(invoker's cert,tx.payload||tx.Binding)
func (t *BoundsChaincode) isAuthorized(stub *shim.ChaincodeStub, cert []byte) (bool, error) {
	mylog.Debug("Check caller's auth.")

	sigma, err := stub.GetCallerMetadata()
	if err != nil {
		return false, errors.New("Failed getting metadata")
	}
	payload, err := stub.GetPayload()
	if err != nil {
		return false, errors.New("Failed getting payload")
	}
	binding, err := stub.GetBinding()
	if err != nil {
		return false, errors.New("Failed getting metadata")
	}

	mylog.Debugf("passed cert [%x]", cert)
	mylog.Debugf("passed sigma [%x]", sigma)
	mylog.Debugf("passed binding [%x]", binding)

	ok, err := stub.VerifySignature(
		cert,
		sigma,
		append(payload, binding...),
	)
	if err != nil {
		mylog.Errorf("Failed checking signature [%s]", err)
		return ok, err
	}
	if !ok {
		mylog.Errorf("Invalid signature")
	}

	mylog.Debug("Check caller...Done!")

	return ok, err
}

// Assign
// 登记账号并记录初始积分
// args[0] = 账户ID，为某注册账户的Public Ecert
func (t *BoundsChaincode) assign(stub *shim.ChaincodeStub, args []string) ([]byte, error) {
	mylog.Debug("Assign AccountID")

	if len(args) != 1 {
		return nil, errors.New("Incorrect number of arguments.Expecting 1")
	}

	account := args[0]
	var bounds int64

	// 确认调用该合约assign函数的调用者身份，必须是admin
	// 若不是，不能允许调用assign
	// adminCert, err := stub.GetState("admin")
	// if err != nil {
	// 	return nil, errors.New("Failed fetching admin identity")
	// }
	//
	// ok, err := t.isAuthorized(stub, adminCert)
	// if err != nil {
	// 	return nil, errors.New("Failed checking admin identity")
	// }
	// if !ok {
	// 	return nil, errors.New("The caller is not an administrator")
	// }

	mylog.Debugf("New user [%s] has been added", account)

	bounds = 0
	ok, err := stub.InsertRow(tableTitle, shim.Row{
		Columns: []*shim.Column{
			&shim.Column{Value: &shim.Column_String_{String_: account}},
			&shim.Column{Value: &shim.Column_Int64{Int64: bounds}}},
	})

	if !ok && err == nil {
		return nil, errors.New("Account was already assigned.")
	}

	mylog.Debug("Assign...Done!")

	return nil, err
}

// transfer 进行积分转账
// args[0] 积分源账户Tcert
// args[1] 积分目的账户Tcert
// args[2] 积分转账金额
func (t *BoundsChaincode) transfer(stub *shim.ChaincodeStub, args []string) ([]byte, error) {
	mylog.Debug("Transfering bounds starts")

	if len(args) != 3 {
		return nil, errors.New("Incorrect number of arguments.Expecting 3")
	}

	fromBalance, err := t.queryBalance(stub, args[0])
	if err != nil {
		return nil, errors.New("error in getting account record")
	}
	toBalance, err := t.queryBalance(stub, args[1])
	if err != nil {
		return nil, errors.New("error in getting account record")
	}

	fromAccount := args[0]
	toAccount := args[1]

	amount, err := strconv.ParseInt(args[2], 10, 64)
	if err != nil {
		return nil, errors.New("Unable to parse amount" + args[2])
	}

	// 确认调用该合约assign函数的调用者身份，必须是admin
	// 若不是，不能允许调用assign
	// adminCert, err := stub.GetState("admin")
	// if err != nil {
	// 	return nil, errors.New("Failed fetching admin identity")
	// }
	//
	// ok, err := t.isAuthorized(stub, adminCert)
	// if err != nil {
	// 	return nil, errors.New("Failed checking admin identity")
	// }
	// if !ok {
	// 	return nil, errors.New("The caller is not an administrator")
	// }

	if amount > 0 {
		if amount > fromBalance {
			mylog.Debug("the Account has not enought bounds")
			return nil, errors.New("Balance not enough")
		}
		fromBalance -= amount
		toBalance += amount
		t.updateAccountBalance(stub, fromAccount, fromBalance)
		t.updateAccountBalance(stub, toAccount, toBalance)
	}

	mylog.Debug("Transfer bounds...Done! ")
	return nil, err
}

// getBalance 获取某一AccountID下的积分余额
// args[0] = accountID
func (t *BoundsChaincode) getBalance(stub *shim.ChaincodeStub, args []string) ([]byte, error) {
	mylog.Debug("===getBalance===")

	if len(args) < 1 {
		return nil, errors.New("Incorrect number of arguments. Expecting 1")
	}

	balance, err := t.queryBalance(stub, args[0])
	if err != nil {
		return nil, err
	}
	mylog.Debugf("[%v]", balance)

	var ret []byte
	ret = strconv.AppendInt(ret, balance, 10)
	mylog.Debugf("[%s]", ret)

	return ret, nil
}

// queryBalance查询积分余额
// accountID ： string accountID
func (t *BoundsChaincode) queryBalance(stub *shim.ChaincodeStub, accountID string) (int64, error) {

	row, err := t.queryTable(stub, accountID)
	if err != nil {
		return 0, err
	}
	if len(row.Columns) == 0 || row.Columns[1] == nil {
		return 0, errors.New("row or column value not found")
	}

	return row.Columns[1].GetInt64(), nil
}

// queryTable 返回对应某一accountID的某一行
// stub: chaincodestub
// accountID: accountID
func (t *BoundsChaincode) queryTable(stub *shim.ChaincodeStub, accountID string) (shim.Row, error) {

	var columns []shim.Column
	col1 := shim.Column{Value: &shim.Column_String_{String_: accountID}}
	columns = append(columns, col1)

	return stub.GetRow(tableTitle, columns)
}

// updateAccountBalance updates the balance amount of an account ID
// stub: chaincodestub
// accountID: account will be updated with the new balance
// amount: new amount to be udpated with
func (t *BoundsChaincode) updateAccountBalance(stub *shim.ChaincodeStub,
	accountID string,
	amount int64) error {

	mylog.Debugf("insert accountID= %v", accountID)

	//replace the old record row associated with the account ID with the new record row
	ok, err := stub.ReplaceRow(tableTitle, shim.Row{
		Columns: []*shim.Column{
			&shim.Column{Value: &shim.Column_String_{String_: accountID}},
			&shim.Column{Value: &shim.Column_Int64{Int64: amount}}},
	})

	if !ok && err == nil {
		mylog.Errorf("system error %v", err)
		return errors.New("failed to replace row with account Id  " + string(accountID))
	}

	return nil
}

func main() {
	primitives.SetSecurityLevel("SHA3", 256)
	err := shim.Start(new(BoundsChaincode))
	if err != nil {
		fmt.Printf("Error starting Bounds Chaincode: %s\n", err)
	}
}
