package model

type HostBinding struct {
	HomeHost   HomeHost `json:"-"           gorm:"ForeignKey:HostID;AssociationForeignKey:Id"`
	HostID     uint     `json:"host_id"     gorm:"primary_key"`
	User       User     `json:"-"           gorm:"ForeignKey:UserID;AssociationForeignKey:Id"`
	UserID     uint     `json:"user_id"`
	ScreenName string   `json:"screen_name" gorm:"default:'Home Host'"`
	CreatedAt  JsonTime `json:"created_at"`
}
