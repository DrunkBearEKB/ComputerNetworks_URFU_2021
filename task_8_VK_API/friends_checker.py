import vk
import argparse
import math
import os


TOKEN = 'f321f289c91e15f4010a2dfc3e15093e735b7e7485c' \
        '06cce3ae05f6109c60b99dfb977a10389fd9a17b22'
VK_API_VERSION = '5.21'


def user_to_string(user):
    return f'{user["last_name"]} {user["first_name"]}'


def output(string, args):
    if args.save:
        with open(f'friends_{args.id}.txt', mode='a') as file:
            file.write(f'{string}\n')
    else:
        print(string)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('id', type=int, help='users_id')
    parser.add_argument('-t', '--table', action='store_true',
                        help='show results as a table')
    parser.add_argument('-s', '--save', action='store_true',
                        help='saves result in file')
    args = parser.parse_args()

    try:
        session = vk.Session(access_token=TOKEN)
        vk_api = vk.API(session)
        user = vk_api.users.get(user_id=args.id, v=VK_API_VERSION)[0]
    except Exception:
        print('An error occurred during the execution of the program!'
              'Please check the correctness of the data you entered, '
              'and also check your internet connection.')
        return

    if not args.save:
        output(
            f'Friends of user [{user_to_string(user)}] with id [{args.id}]:',
            args)
    else:
        with open(f'friends_{args.id}.txt', mode='w') as file:
            pass

    list_id_friends = vk_api.friends.get(user_id=user['id'], v=VK_API_VERSION)
    for i in range(math.ceil(list_id_friends['count'] / 1000)):
        _slice = list_id_friends['items'][1000 * i: 1000 * (i + 1)]
        ids_current = ','.join(map(str, _slice))
        list_friends = vk_api.users.get(user_ids=ids_current, v=VK_API_VERSION)
        list_friends.sort(key=lambda _user: user_to_string(_user))

        id_len = 0
        name_len = 0
        for friend in list_friends:
            id_len = max(id_len, len(str(friend['id'])))
            name_len = max(name_len, len(user_to_string(friend)))

        if args.table:
            output('-' * (2 + id_len + 3 + name_len + 2), args)
            output('| ID' + ' ' * (id_len - 2) + ' | NAME' +
                   ' ' * (name_len - 4) + ' |', args)
            output('-' * (2 + id_len + 3 + name_len + 2), args)
            for friend in list_friends:
                if 'deactivated' in friend and \
                        friend['deactivated'] == 'deleted':
                    continue
                output(f'| {friend["id"]}' +
                       ' ' * (id_len - len(str(friend["id"]))) +
                       f' | {user_to_string(friend)}' +
                       ' ' * (name_len - len(user_to_string(friend))) +
                       ' |', args)
            output('-' * (2 + id_len + 3 + name_len + 2), args)
        else:
            for friend in list_friends:
                if 'deactivated' in friend and \
                        friend['deactivated'] == 'deleted':
                    continue
                output('{:<10}'.format(friend['id']) +
                       f' - {user_to_string(friend)}', args)

    if args.save:
        print(f'Successfully saved to \n->\t{os.getcwd()}\\'
              f'friends_{args.id}.txt')


if __name__ == '__main__':
    main()
