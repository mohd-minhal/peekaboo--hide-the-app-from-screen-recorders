import argparse
from handle_capture import capture_window_handle_and_pid
from process_injector import inject_code

def main():
    parser = argparse.ArgumentParser(description='Command-line utility for various processes.')
    parser.add_argument('action', choices=['capture', 'inject'], help='The action to perform')
    parser.add_argument('--option', help='Additional option for the selected action')

    args = parser.parse_args()

    if args.action == 'capture':
        window_handle, process_id = capture_window_handle_and_pid(args.option)

    elif args.action == 'inject':
        window_handle, process_id = capture_window_handle_and_pid(args.option)
        inject_code(process_id,window_handle)

if __name__ == '__main__':
    main()