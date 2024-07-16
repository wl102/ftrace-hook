package main

import (
	"fmt"
	"log"
	"os"
	"os/signal"

	"github.com/mdlayher/netlink"
)

const NETLINK_USER = 25

func main() {
	c, err := netlink.Dial(NETLINK_USER, &netlink.Config{
		PID: 100,
	})
	if err != nil {
		log.Fatalf("failed to dial netlink: %v", err)
	}
	defer c.Close()

	//退出
	defer func() {
		if _, err := c.Send(netlink.Message{
			Header: netlink.Header{
				Type:  0,
				Flags: netlink.Request,
			},
			Data: []byte("3"),
		}); err != nil {
			log.Fatalf("failed to send netlink message: %v", err)
		}
	}()
	interrupt := make(chan os.Signal, 1)
	exit := make(chan struct{}, 1)
	signal.Notify(interrupt, os.Interrupt, os.Kill)

	//启用
	if _, err := c.Send(netlink.Message{
		Header: netlink.Header{
			Type:  0,
			Flags: netlink.Request,
		},
		Data: []byte("2"),
	}); err != nil {
		log.Fatalf("failed to send netlink message: %v", err)
	}

	go func() {
		defer func() {
			err := recover()
			log.Println(err)
			exit <- struct{}{}
		}()

		for {
			msgs, err := c.Receive()
			if err != nil {
				log.Fatalf("failed to receive netlink messages: %v", err)
			}
			//n := rand.Intn(200)
			for _, m := range msgs {
				seq := m.Header.Sequence
				// 去掉 '\0' char
				path := string(TrimNullChar(m.Data))
				fmt.Printf("Received path from kernel: %s, Seq:%d\n", path, seq)

				// 判断文件是否安全
				safe := checkFileSafety(path)

				// 发送结果回内核
				response := []byte("1")
				if !safe {
					response = []byte("0")
				}
				//time.Sleep(time.Duration(n) * time.Millisecond)
				fmt.Printf("send to kernel '%s' seq:%d res:%d\n", path, seq, response)
				if _, err := c.Send(netlink.Message{
					Header: netlink.Header{
						Type:     0,
						Flags:    netlink.Request,
						Sequence: seq,
					},
					Data: response,
				}); err != nil {
					log.Fatalf("failed to send netlink message: %v", err)
				}
			}
		}
	}()

	select {
	case <-interrupt:
		fmt.Println("\ninterrupt")
		return
	case <-exit:
		fmt.Println("\nexit")
		return
	}
}

func checkFileSafety(path string) bool {
	// 在这里实现判断逻辑
	return path != "/home/kolla/hello_world/main"
}

func TrimNullChar(data []byte) []byte {
	for i := 0; i < len(data); i++ {
		if data[i] == 0x00 {
			return data[:i]
		}
	}
	return data
}
