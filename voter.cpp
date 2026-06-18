#define main original_main
#include "core.cpp"
#undef main

int main()
{
    Blockchain bc;

    while(true)
    {
        bc.load_blockchain();

        cout<<"\n=============================================="<<endl;
        cout<<"           VOTER TERMINAL"<<endl;
        cout<<"=============================================="<<endl;
        cout<<"1. Register (Create Voter Account)"<<endl;
        cout<<"2. Login   (Cast Your Vote)"<<endl;
        cout<<"3. Exit"<<endl;
        cout<<"Choice: ";

        int choice;
        if(!(cin>>choice))
        {
            cin.clear();
            cin.ignore(10000,'\n');
            cout<<">>> Enter 1, 2, or 3."<<endl;
            continue;
        }

        if(choice==1)
        {
            user_registration(bc);
        }
        else if(choice==2)
        {
            user_login(bc);
        }
        else if(choice==3)
        {
            cout<<">>> Goodbye."<<endl;
            break;
        }
        else
        {
            cout<<">>> Invalid option."<<endl;
        }
    }

    return 0;
}