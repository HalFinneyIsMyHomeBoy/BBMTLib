package tss

type HookListener interface {
	OnMessage(message string)
}

var hookListener HookListener

func SetHookListener(h HookListener) {
	hookListener = h
}

func Hook(message string) {
	if hookListener != nil {
		hookListener.OnMessage(message)
	}
	Logln(message)
}
